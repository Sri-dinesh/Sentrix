import asyncio
import json
from typing import Set, Dict, Any, AsyncGenerator


class EventBroadcaster:
    """
    In-memory async Pub/Sub event broadcaster for Server-Sent Events (SSE).
    Allows ingestion workers and domain services to stream real-time events to frontend dashboards.
    """

    def __init__(self):
        self._subscribers: Set[asyncio.Queue] = set()

    async def publish(self, event_type: str, data: Dict[str, Any]):
        """
        Broadcasts a typed event payload to all currently connected SSE clients.
        """
        payload = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
        dead_queues = set()
        for q in self._subscribers:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                dead_queues.add(q)
            except Exception:
                dead_queues.add(q)

        for dq in dead_queues:
            self._subscribers.discard(dq)

    async def subscribe(self) -> AsyncGenerator[str, None]:
        """
        Subscribes an SSE client and yields formatted event strings.
        """
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._subscribers.add(q)
        try:
            # Yield initial connection heartbeat
            yield f"event: connected\ndata: {json.dumps({'message': 'Connected to Sentrix SSE Stream'})}\n\n"
            while True:
                data = await q.get()
                yield data
        except asyncio.CancelledError:
            pass
        finally:
            self._subscribers.discard(q)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


_broadcaster_instance: EventBroadcaster = EventBroadcaster()


def get_event_broadcaster() -> EventBroadcaster:
    return _broadcaster_instance
