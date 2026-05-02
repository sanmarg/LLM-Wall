# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Immutable blockchain audit ledger for LLM Wall security events.

Implements a SHA-256 linked-list blockchain with proof-of-work (PoW)
mining, Merkle tree per-block integrity, and JSON persistence.

Design notes:
    - Each block stores a list of AuditEvents (≤50 events per block).
    - PoW difficulty is configurable (default=2, fast lab-grade).
    - Chain integrity is verified via hash-linking and Merkle roots.
    - No external chain / crypto wallet required.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from llm_wall.config import get_settings
from llm_wall.ledger.merkle import MerkleTree
from llm_wall.models import AuditEvent, BlockData

logger = logging.getLogger(__name__)

# Maximum events buffered before a new block is mined automatically.
_MAX_PENDING_EVENTS: int = 50


# ---------------------------------------------------------------------------
# Block
# ---------------------------------------------------------------------------


class Block:
    """A single immutable block in the audit ledger chain.

    Attributes:
        index: Sequential block number (genesis = 0).
        timestamp: UTC ISO-8601 creation time.
        data: Serialised BlockData payload.
        previous_hash: Hash of the previous block ('' for genesis).
        merkle_root: Merkle root of block events for integrity.
        nonce: PoW nonce found during mining.
        hash: This block's SHA-256 hash (computed after mining).
    """

    def __init__(
        self,
        index: int,
        data: BlockData,
        previous_hash: str,
        difficulty: int = 2,
    ) -> None:
        """Creates and immediately mines a new block.

        Args:
            index: Sequential block index.
            data: BlockData payload to store.
            previous_hash: Hash of the preceding block.
            difficulty: PoW leading-zero difficulty.
        """
        self.index: int = index
        self.timestamp: str = datetime.now(timezone.utc).isoformat()
        self.data: BlockData = data
        self.previous_hash: str = previous_hash
        self.difficulty: int = difficulty
        self.merkle_root: str = self._compute_merkle_root()
        self.nonce: int = 0
        self.hash: str = self._mine()

    def _compute_merkle_root(self) -> str:
        """Computes the Merkle root over serialised event IDs.

        Returns:
            Merkle root hex string.  Returns SHA-256 of 'empty' if no events.
        """
        if not self.data.events:
            return hashlib.sha256(b"empty").hexdigest()
        items = [e.model_dump_json() for e in self.data.events]
        return MerkleTree(items).root_hash

    def _compute_hash(self) -> str:
        """Computes SHA-256 hash of this block's header fields.

        Returns:
            64-character hex hash string.
        """
        header = (
            f"{self.index}"
            f"{self.timestamp}"
            f"{self.data.model_dump_json()}"
            f"{self.previous_hash}"
            f"{self.merkle_root}"
            f"{self.nonce}"
        )
        return hashlib.sha256(header.encode()).hexdigest()

    def _mine(self) -> str:
        """Finds a nonce satisfying the proof-of-work difficulty.

        Returns:
            Valid block hash with the required leading zeros.
        """
        prefix = "0" * self.difficulty
        t0 = time.perf_counter()
        candidate = self._compute_hash()
        while not candidate.startswith(prefix):
            self.nonce += 1
            candidate = self._compute_hash()
        elapsed = (time.perf_counter() - t0) * 1000
        logger.debug(
            "Block #%d mined: nonce=%d hash=%s... (%.1fms)",
            self.index,
            self.nonce,
            candidate[:12],
            elapsed,
        )
        return candidate

    def to_dict(self) -> dict[str, Any]:
        """Serialises the block to a JSON-compatible dictionary.

        Returns:
            Dict with all block fields.
        """
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": json.loads(self.data.model_dump_json()),
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "nonce": self.nonce,
            "hash": self.hash,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Block":
        """Reconstructs a Block from a persisted dictionary.

        Args:
            raw: Dict produced by ``to_dict``.

        Returns:
            Block instance (without re-mining; hash taken from storage).
        """
        block = object.__new__(cls)
        block.index = raw["index"]
        block.timestamp = raw["timestamp"]
        block.data = BlockData(**raw["data"])
        block.previous_hash = raw["previous_hash"]
        block.merkle_root = raw["merkle_root"]
        block.nonce = raw["nonce"]
        block.hash = raw["hash"]
        block.difficulty = len(raw["hash"]) - len(raw["hash"].lstrip("0"))
        return block


# ---------------------------------------------------------------------------
# Blockchain
# ---------------------------------------------------------------------------


class Blockchain:
    """SHA-256 linked-list blockchain for immutable security audit logging.

    Example:
        >>> chain = Blockchain(node_id="node-1")
        >>> chain.add_event(some_audit_event)
        >>> chain.flush()           # mine pending events as a new block
        >>> print(chain.is_valid())  # True
    """

    def __init__(
        self,
        node_id: str,
        difficulty: int | None = None,
        persist_path: str | None = None,
    ) -> None:
        """Initialises the blockchain and loads from disk if available.

        Args:
            node_id: Unique identifier of this ledger node.
            difficulty: PoW difficulty; falls back to config if None.
            persist_path: Filesystem path for JSON persistence.
        """
        cfg = get_settings()
        self._node_id: str = node_id
        self._difficulty: int = difficulty or cfg.ledger_difficulty
        self._persist_path: Path = Path(
            persist_path or cfg.ledger_persist_path
        )
        self._pending_events: list[AuditEvent] = []
        self.chain: list[Block] = []

        if self._persist_path.exists():
            self._load()
        else:
            self._create_genesis()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_event(self, event: AuditEvent) -> None:
        """Adds an audit event to the pending buffer.

        Automatically mines a new block when the buffer is full.

        Args:
            event: AuditEvent to record.
        """
        self._pending_events.append(event)
        logger.debug(
            "Ledger pending: %d events (block #%d)",
            len(self._pending_events),
            len(self.chain),
        )
        if len(self._pending_events) >= _MAX_PENDING_EVENTS:
            self.flush()

    def flush(self, iocs_added: list[str] | None = None) -> Block | None:
        """Mines all pending events into a new block.

        Args:
            iocs_added: Optional list of IOC IDs to include in block data.

        Returns:
            The newly mined Block, or None if there are no pending events.
        """
        if not self._pending_events:
            return None
        data = BlockData(
            events=list(self._pending_events),
            iocs_added=iocs_added or [],
            node_id=self._node_id,
        )
        block = Block(
            index=len(self.chain),
            data=data,
            previous_hash=self.chain[-1].hash if self.chain else "0" * 64,
            difficulty=self._difficulty,
        )
        self.chain.append(block)
        self._pending_events.clear()
        self._persist()
        logger.info(
            "Block #%d mined: events=%d hash=%s",
            block.index,
            len(data.events),
            block.hash[:16],
        )
        return block

    def is_valid(self) -> bool:
        """Verifies the integrity of the entire chain.

        Checks that every block's stored hash matches a recomputed hash
        and that each block correctly references its predecessor.

        Returns:
            True if the chain is intact, False if tampered.
        """
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            if current.previous_hash != previous.hash:
                logger.error(
                    "Chain break at block #%d: prev_hash mismatch.", i
                )
                return False
            recomputed = current._compute_hash()  # pylint: disable=protected-access
            if recomputed != current.hash:
                logger.error(
                    "Block #%d hash invalid (tampered).", i
                )
                return False
        return True

    def get_block(self, index: int) -> Block | None:
        """Returns the block at the given index.

        Args:
            index: Zero-based block index.

        Returns:
            Block instance or None if index is out of range.
        """
        if 0 <= index < len(self.chain):
            return self.chain[index]
        return None

    def export_chain(self) -> list[dict[str, Any]]:
        """Exports the full chain as a list of dicts.

        Returns:
            List of block dictionaries in ascending index order.
        """
        return [b.to_dict() for b in self.chain]

    def get_merkle_proof(
        self, block_index: int, event_id: str
    ) -> dict[str, Any]:
        """Returns a Merkle inclusion proof for an event in a block.

        Args:
            block_index: Index of the block containing the event.
            event_id: UUID of the AuditEvent to prove.

        Returns:
            Dict with 'root', 'proof', and 'valid' keys.
            Returns an error dict if the block or event is not found.
        """
        block = self.get_block(block_index)
        if not block:
            return {"error": f"Block #{block_index} not found."}
        items = [e.model_dump_json() for e in block.data.events]
        if not items:
            return {"error": "Block has no events."}
        target_item: str | None = None
        for event in block.data.events:
            if event.event_id == event_id:
                target_item = event.model_dump_json()
                break
        if not target_item:
            return {"error": f"Event {event_id} not in block #{block_index}."}
        tree = MerkleTree(items)
        proof = tree.get_proof(target_item)
        valid = MerkleTree.verify_proof(target_item, proof, tree.root_hash)
        return {
            "block_index": block_index,
            "event_id": event_id,
            "merkle_root": tree.root_hash,
            "proof": proof,
            "valid": valid,
        }

    @property
    def height(self) -> int:
        """Returns the current chain height (number of blocks).

        Returns:
            Integer block count.
        """
        return len(self.chain)

    @property
    def pending_count(self) -> int:
        """Returns the count of buffered but un-mined events.

        Returns:
            Integer pending event count.
        """
        return len(self._pending_events)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _persist(self) -> None:
        """Persists the chain to the configured JSON file."""
        self._persist_path.parent.mkdir(parents=True, exist_ok=True)
        with self._persist_path.open("w", encoding="utf-8") as fp:
            json.dump(self.export_chain(), fp, indent=2)

    def _load(self) -> None:
        """Loads the chain from the persisted JSON file."""
        with self._persist_path.open("r", encoding="utf-8") as fp:
            raw_chain = json.load(fp)
        self.chain = [Block.from_dict(b) for b in raw_chain]
        logger.info(
            "Ledger loaded: %d blocks from %s",
            len(self.chain),
            self._persist_path,
        )

    def _create_genesis(self) -> None:
        """Creates the genesis block (block #0)."""
        genesis_data = BlockData(
            events=[],
            iocs_added=[],
            node_id=self._node_id,
        )
        genesis = Block(
            index=0,
            data=genesis_data,
            previous_hash="0" * 64,
            difficulty=self._difficulty,
        )
        self.chain.append(genesis)
        self._persist()
        logger.info("Genesis block mined: hash=%s", genesis.hash[:16])
