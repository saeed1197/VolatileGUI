"""
In-process pub/sub used to push live job events to browsers over SSE.

Publishers are worker *threads*; subscribers are asyncio SSE handlers, so
publish() hops onto the event loop with call_soon_threadsafe.
"""

from __future__ import annotations

import asyncio
import json
import threading
from collections import defaultdict, deque
from typing import Any, Deque, Dict, Set

MAX_QUEUE = 2000
REPLAY = 400


class Broker:
    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._subs: Dict[str, Set[asyncio.Queue]] = defaultdict(set)
        self._history: Dict[str, Deque[dict]] = defaultdict(lambda: deque(maxlen=REPLAY))
        self._lock = threading.Lock()

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    # -- subscriber side (async) -------------------------------------------
    def subscribe(self, topic: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=MAX_QUEUE)
        with self._lock:
            self._subs[topic].add(q)
        return q

    def unsubscribe(self, topic: str, q: asyncio.Queue) -> None:
        with self._lock:
            self._subs[topic].discard(q)
            if not self._subs[topic]:
                self._subs.pop(topic, None)

    def history(self, topic: str) -> list:
        with self._lock:
            return list(self._history.get(topic, ()))

    def clear(self, topic: str) -> None:
        with self._lock:
            self._history.pop(topic, None)

    # -- publisher side (thread-safe) ---------------------------------------
    def publish(self, topic: str, payload: Any, keep: bool = True) -> None:
        if keep:
            with self._lock:
                self._history[topic].append(payload)
        with self._lock:
            targets = list(self._subs.get(topic, ()))
        if not targets:
            return
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        for q in targets:
            try:
                loop.call_soon_threadsafe(_offer, q, payload)
            except RuntimeError:
                pass


def _offer(q: asyncio.Queue, payload: Any) -> None:
    try:
        q.put_nowait(payload)
    except asyncio.QueueFull:
        try:
            q.get_nowait()
            q.put_nowait(payload)
        except Exception:
            pass


broker = Broker()


def sse(event: str, data: Any) -> str:
    """Format one Server-Sent Event frame."""
    body = data if isinstance(data, str) else json.dumps(data, default=str)
    lines = "".join(f"data: {chunk}\n" for chunk in body.split("\n"))
    return f"event: {event}\n{lines}\n"
