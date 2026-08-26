import json
from fastapi import APIRouter, Request, HTTPException, status, Depends
from sqlalchemy.orm import Session
from svix.webhooks import Webhook, WebhookVerificationError
from app.core.config import settings
from app.db.session import get_db
from app.repositories import user_repository

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


@router.post("/clerk")
async def handle_clerk_webhook(
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Receives and processes Clerk webhook events to synchronize users into Supabase.
    """
    payload_bytes = await request.body()
    headers = request.headers

    svix_id = headers.get("svix-id")
    svix_timestamp = headers.get("svix-timestamp")
    svix_signature = headers.get("svix-signature")

    # If webhook secret is configured and not placeholder, verify with svix
    if (
        settings.CLERK_WEBHOOK_SECRET
        and settings.CLERK_WEBHOOK_SECRET != "whsec_placeholder"
        and not settings.CLERK_WEBHOOK_SECRET.startswith("whsec_placeholder")
    ):
        if not svix_id or not svix_timestamp or not svix_signature:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing required Svix webhook headers",
            )
        try:
            wh = Webhook(settings.CLERK_WEBHOOK_SECRET)
            payload_str = payload_bytes.decode("utf-8")
            event_data = wh.verify(
                payload_str,
                {
                    "svix-id": svix_id,
                    "svix-timestamp": svix_timestamp,
                    "svix-signature": svix_signature,
                },
            )
        except WebhookVerificationError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid webhook signature: {str(e)}",
            )
    else:
        # Development / test fallback
        try:
            event_data = json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid JSON payload",
            )

    event_type = event_data.get("type", "")
    data = event_data.get("data", {})

    if event_type in ("user.created", "user.updated"):
        clerk_user_id = data.get("id")
        email_addresses = data.get("email_addresses", [])
        primary_email_id = data.get("primary_email_address_id")

        primary_email = None
        for email_obj in email_addresses:
            if email_obj.get("id") == primary_email_id:
                primary_email = email_obj.get("email_address")
                break
        if not primary_email and email_addresses:
            primary_email = email_addresses[0].get("email_address")

        if clerk_user_id and primary_email:
            user = user_repository.upsert_user_from_clerk(
                db=db,
                clerk_user_id=clerk_user_id,
                email=primary_email,
                role="analyst",
            )
            return {"status": "success", "event": event_type, "user_id": str(user.id)}

    return {"status": "ignored", "event": event_type}
