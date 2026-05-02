# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Merkle tree implementation for blockchain block integrity proofs.

Provides a binary Merkle tree built from SHA-256 hashes, enabling
efficient inclusion proofs for individual audit events.

Reference: https://en.wikipedia.org/wiki/Merkle_tree
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


def _sha256(data: str) -> str:
    """Returns the hex-encoded SHA-256 hash of a UTF-8 string.

    Args:
        data: Input string to hash.

    Returns:
        64-character lowercase hex string.
    """
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass
class MerkleNode:
    """A node in the Merkle binary tree.

    Attributes:
        hash_value: SHA-256 hash of this node's data.
        left: Optional left child node.
        right: Optional right child node.
    """

    hash_value: str
    left: Optional["MerkleNode"] = field(default=None, repr=False)
    right: Optional["MerkleNode"] = field(default=None, repr=False)

    @property
    def is_leaf(self) -> bool:
        """Returns True if the node is a leaf (no children).

        Returns:
            Boolean indicating leaf status.
        """
        return self.left is None and self.right is None


class MerkleTree:
    """Binary Merkle tree for audit event integrity verification.

    Builds a complete binary tree from a list of data strings. Leaf
    nodes store SHA-256 hashes of individual items; parent nodes store
    the hash of the concatenation of their children's hashes.

    Example:
        >>> tree = MerkleTree(["event_a", "event_b", "event_c"])
        >>> root = tree.root_hash
        >>> proof = tree.get_proof("event_a")
        >>> MerkleTree.verify_proof("event_a", proof, root)
        True
    """

    def __init__(self, items: list[str]) -> None:
        """Constructs the Merkle tree from a list of data items.

        Args:
            items: Ordered list of serialised data items (e.g. JSON strings).

        Raises:
            ValueError: If items is empty.
        """
        if not items:
            raise ValueError("MerkleTree requires at least one item.")
        self._leaves: list[str] = items
        self._leaf_nodes: list[MerkleNode] = [
            MerkleNode(hash_value=_sha256(item)) for item in items
        ]
        self._root: MerkleNode = self._build_tree(self._leaf_nodes)
        logger.debug(
            "MerkleTree built: leaves=%d root=%s",
            len(items),
            self._root.hash_value[:12],
        )

    @property
    def root_hash(self) -> str:
        """Returns the root hash of the Merkle tree.

        Returns:
            64-character hex root hash string.
        """
        return self._root.hash_value

    def _build_tree(self, nodes: list[MerkleNode]) -> MerkleNode:
        """Recursively builds the Merkle tree from leaf nodes.

        Args:
            nodes: Current level of nodes to combine.

        Returns:
            Root MerkleNode of the built tree.
        """
        if len(nodes) == 1:
            return nodes[0]
        # Duplicate last node if odd count (standard Merkle padding)
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])
        parent_nodes: list[MerkleNode] = []
        for i in range(0, len(nodes), 2):
            left, right = nodes[i], nodes[i + 1]
            combined = _sha256(left.hash_value + right.hash_value)
            parent_nodes.append(
                MerkleNode(hash_value=combined, left=left, right=right)
            )
        return self._build_tree(parent_nodes)

    def get_proof(self, item: str) -> list[dict[str, str]]:
        """Generates an inclusion proof for a data item.

        Args:
            item: The original data string to prove inclusion for.

        Returns:
            List of dicts with keys 'position' ('left'|'right') and
            'hash' representing sibling hashes along the proof path.
            Returns empty list if the item is not in the tree.
        """
        item_hash = _sha256(item)
        target_idx: int | None = None
        for i, leaf in enumerate(self._leaf_nodes):
            if leaf.hash_value == item_hash:
                target_idx = i
                break
        if target_idx is None:
            logger.warning("Item not found in Merkle tree: %s", item[:40])
            return []

        proof: list[dict[str, str]] = []
        nodes = list(self._leaf_nodes)
        idx = target_idx

        while len(nodes) > 1:
            if len(nodes) % 2 == 1:
                nodes.append(nodes[-1])
            if idx % 2 == 0:
                sibling_idx = idx + 1
                proof.append(
                    {"position": "right", "hash": nodes[sibling_idx].hash_value}
                )
            else:
                sibling_idx = idx - 1
                proof.append(
                    {"position": "left", "hash": nodes[sibling_idx].hash_value}
                )
            parent_nodes: list[MerkleNode] = []
            for i in range(0, len(nodes), 2):
                left, right = nodes[i], nodes[i + 1]
                combined = _sha256(left.hash_value + right.hash_value)
                parent_nodes.append(MerkleNode(hash_value=combined))
            idx = idx // 2
            nodes = parent_nodes

        return proof

    @staticmethod
    def verify_proof(
        item: str,
        proof: list[dict[str, str]],
        root_hash: str,
    ) -> bool:
        """Verifies a Merkle inclusion proof against a known root hash.

        Args:
            item: The original data string to verify.
            proof: Proof list returned by ``get_proof``.
            root_hash: The expected Merkle root hash.

        Returns:
            True if the proof is valid for the given root, False otherwise.
        """
        current_hash = _sha256(item)
        for step in proof:
            sibling = step["hash"]
            if step["position"] == "right":
                current_hash = _sha256(current_hash + sibling)
            else:
                current_hash = _sha256(sibling + current_hash)
        return current_hash == root_hash
