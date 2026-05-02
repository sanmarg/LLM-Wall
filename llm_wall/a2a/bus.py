# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Agent-to-Agent (A2A) message bus.

Provides an async pub/sub message bus for intra-process agent
communication. Supports topic-based subscription, priority queues,
and a WebSocket bridge for external agent connectivity.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Any, Awaitable, Callable

from llm_wall.models import A2AMessage

logger = logging.getLogger(__name__)

# Type alias for message handler coroutines.
MessageHandler = Callable[[A2AMessage], Awaitable[None]]


class A2ABus:
    """Async pub/sub message bus for Agent-to-Agent communication.

    Agents subscribe to named topics and receive all messages published
    to those topics. Handlers are called concurrently with asyncio.gather.

    Example:
        >>> bus = A2ABus()
        >>> async def on_threat(msg: A2AMessage) -> None:
        ...     print(msg.payload)
        >>> bus.subscribe("threat.detected", on_threat)
        >>> await bus.publish(A2AMessage(
        ...     sender_id="guardian", topic="threat.detected",
        ...     payload={"risk": 85}))
    """

    def __init__(self) -> None:
        """Initialises the bus with empty subscription tables."""
        self._subscribers: dict[str, list[MessageHandler]] = defaultdict(list)
        self._message_log: list[A2AMessage] = []
        self._max_log: int = 1000
        self._publish_count: int = 0

    def subscribe(self, topic: str, handler: MessageHandler) -> None:
        """Registers a handler for a given topic.

        Args:
            topic: Topic string (e.g. 'threat.detected', 'ioc.new').
            handler: Async callable accepting an A2AMessage.
        """
        self._subscribers[topic].append(handler)
        logger.debug(
            "A2A subscribe: topic=%s handler=%s",
            topic,
            handler.__qualname__,
        )

    def unsubscribe(self, topic: str, handler: MessageHandler) -> None:
        """Removes a handler from a topic subscription.

        Args:
            topic: Topic name.
            handler: The handler to remove.
        """
        handlers = self._subscribers.get(topic, [])
        if handler in handlers:
            handlers.remove(handler)

    async def publish(self, message: A2AMessage) -> int:
        """Publishes a message to all subscribed handlers on the topic.

        Args:
            message: A2AMessage to broadcast.

        Returns:
            Number of handlers that received the message.
        """
        self._publish_count += 1
        self._message_log.append(message)
        if len(self._message_log) > self._max_log:
            self._message_log.pop(0)

        handlers = self._subscribers.get(message.topic, [])
        if not handlers:
            logger.debug(
                "A2A publish: topic=%s (no subscribers)", message.topic
            )
            return 0

        logger.debug(
            "A2A publish: topic=%s handlers=%d priority=%d",
            message.topic,
            len(handlers),
            message.priority,
        )
        results = await asyncio.gather(
            *[handler(message) for handler in handlers],
            return_exceptions=True,
        )
        errors = [r for r in results if isinstance(r, Exception)]
        if errors:
            logger.warning(
                "A2A handler errors on topic=%s: %s", message.topic, errors
            )
        return len(handlers) - len(errors)

    def get_recent_messages(
        self, topic: str | None = None, limit: int = 50
    ) -> list[A2AMessage]:
        """Returns recent messages from the bus log.

        Args:
            topic: Optional topic filter. If None, returns all topics.
            limit: Maximum number of messages to return.

        Returns:
            List of A2AMessage objects, newest first.
        """
        msgs = list(reversed(self._message_log))
        if topic:
            msgs = [m for m in msgs if m.topic == topic]
        return msgs[:limit]

    def stats(self) -> dict[str, Any]:
        """Returns bus statistics for the dashboard.

        Returns:
            Dict with topic count, subscriber count, and total publishes.
        """
        return {
            "topics": len(self._subscribers),
            "total_subscribers": sum(
                len(h) for h in self._subscribers.values()
            ),
            "total_published": self._publish_count,
            "log_size": len(self._message_log),
        }


# ---------------------------------------------------------------------------
# Well-known topic constants
# ---------------------------------------------------------------------------

TOPIC_THREAT_DETECTED = "threat.detected"
TOPIC_THREAT_BLOCKED = "threat.blocked"
TOPIC_THREAT_QUARANTINED = "threat.quarantined"
TOPIC_IOC_NEW = "ioc.new"
TOPIC_IOC_EVICTED = "ioc.evicted"
TOPIC_LEDGER_BLOCK_MINED = "ledger.block_mined"
TOPIC_SENTINEL_PEER_JOINED = "sentinel.peer_joined"
TOPIC_MARL_DECISION = "marl.decision"
TOPIC_CONSENSUS_REQUEST = "consensus.request"
TOPIC_CONSENSUS_VOTE = "consensus.vote"

# ---------------------------------------------------------------------------
# Module singleton
# ---------------------------------------------------------------------------

_bus_instance: A2ABus | None = None


def get_bus() -> A2ABus:
    """Returns the singleton A2ABus instance.

    Returns:
        Global A2ABus singleton.
    """
    global _bus_instance  # pylint: disable=global-statement
    if _bus_instance is None:
        _bus_instance = A2ABus()
    return _bus_instance
