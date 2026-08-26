from fastapi import APIRouter, Depends
from pydantic import BaseModel
from typing import Optional
import uuid
from datetime import datetime
from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter(prefix="/me", tags=["User Profile"])


class UserProfileResponse(BaseModel):
    id: uuid.UUID
    clerk_user_id: str
    email: str
    role: str
    created_at: datetime

    class Config:
        from_attributes = True


@router.get("", response_model=UserProfileResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user),
):
    """
    Returns authenticated user identity and role from Supabase.
    """
    return current_user
