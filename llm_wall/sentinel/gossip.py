# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Sentinel mesh gossip protocol.

Implements lightweight HTTP-based gossip for threat intel exchange.
Each node periodically syncs its IOC delta to all known peers.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from llm_wall.models import IOC

logger = logging.getLogger(__name__)

_GOSSIP_TIMEOUT_SECS: float = 10.0


class GossipProtocol:
    """HTTP gossip broadcaster for Sentinel mesh nodes.

    Contacts each peer with a delta of IOCs not yet seen by that peer.
    Uses a lightweight push model: senders track what they've sent.

    Example:
        >>> gossip = GossipProtocol(node_id="node-1", peers=["http://node2:8000"])
        >>> await gossip.broadcast_iocs([ioc1, ioc2])
    """

    def __init__(self, node_id: str, peers: list[str]) -> None:
        """Initialises the gossip broadcaster.

        Args:
            node_id: This node's unique ID string.
            peers: List of peer base URLs to broadcast to.
        """
        self._node_id = node_id
        self._peers = peers
        self._sent_ioc_ids: dict[str, set[str]] = {
            peer: set() for peer in peers
        }
        self._broadcast_count: int = 0
        self._client = httpx.AsyncClient(timeout=_GOSSIP_TIMEOUT_SECS)

    async def broadcast_iocs(self, iocs: list[IOC]) -> dict[str, int]:
        """Broadcasts IOCs to all peers (skips already-sent ones).

        Args:
            iocs: List of IOC objects to distribute.

        Returns:
            Dict mapping peer URL to count of IOCs sent to that peer.
        """
        if not self._peers or not iocs:
            return {}

        results: dict[str, int] = {}
        tasks = [
            self._send_to_peer(peer, iocs) for peer in self._peers
        ]
        peer_results = await asyncio.gather(*tasks, return_exceptions=True)
        for peer, result in zip(self._peers, peer_results):
            if isinstance(result, int):
                results[peer] = result
            else:
                logger.warning("Gossip to %s failed: %s", peer, result)
                results[peer] = 0
        self._broadcast_count += 1
        return results

    async def _send_to_peer(self, peer: str, iocs: list[IOC]) -> int:
        """Sends new IOCs to a specific peer node.

        Args:
            peer: Peer base URL.
            iocs: All available IOCs (will filter to unsent).

        Returns:
            Number of IOCs sent to this peer.
        """
        sent_set = self._sent_ioc_ids[peer]
        new_iocs = [i for i in iocs if i.ioc_id not in sent_set]
        if not new_iocs:
            return 0

        payload: dict[str, Any] = {
            "source_node": self._node_id,
            "iocs": [i.model_dump(mode="json") for i in new_iocs],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        try:
            resp = await self._client.post(
                f"{peer}/api/sentinel/gossip",
                json=payload,
                headers={"X-Node-ID": self._node_id},
            )
            resp.raise_for_status()
            for ioc in new_iocs:
                sent_set.add(ioc.ioc_id)
            logger.info(
                "Gossip sent: peer=%s iocs=%d", peer, len(new_iocs)
            )
            return len(new_iocs)
        except httpx.RequestError as exc:
            logger.warning("Gossip HTTP error to %s: %s", peer, exc)
            return 0

    async def heartbeat(self) -> dict[str, bool]:
        """Pings all peers to check liveness.

        Returns:
            Dict mapping peer URL to True (alive) / False (unreachable).
        """
        results: dict[str, bool] = {}
        for peer in self._peers:
            try:
                resp = await self._client.get(
                    f"{peer}/health", timeout=5.0
                )
                results[peer] = resp.status_code < 500
            except Exception:  # pylint: disable=broad-except
                results[peer] = False
        return results

    async def aclose(self) -> None:
        """Closes the underlying HTTP client."""
        await self._client.aclose()

    def stats(self) -> dict[str, Any]:
        """Returns gossip statistics.

        Returns:
            Dict with peer count, broadcast count, and per-peer sent counts.
        """
        return {
            "node_id": self._node_id,
            "peer_count": len(self._peers),
            "broadcast_count": self._broadcast_count,
            "per_peer_sent": {
                peer: len(ids)
                for peer, ids in self._sent_ioc_ids.items()
            },
        }
