from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from app.core.broadcaster import get_event_broadcaster

router = APIRouter(prefix="/stream", tags=["stream"])


@router.get("/events", summary="Subscribe to real-time detection & telemetry stream (SSE)")
async def stream_events_endpoint():
    """
    Subscribes the client to live Server-Sent Events (SSE).
    Streams real-time flow detections, confidence scores, concept drift alerts,
    and autonomous containment actions to dashboard subscribers.
    """
    broadcaster = get_event_broadcaster()
    return StreamingResponse(
        broadcaster.subscribe(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
