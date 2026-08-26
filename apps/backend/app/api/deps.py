from typing import Optional
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.core import security
from app.models.user import User
from app.repositories import user_repository


async def get_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
) -> User:
    """
    Extracts and validates the Clerk session bearer token from request headers.
    Resolves the authenticated User from Supabase, auto-syncing if there is webhook lag.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header is required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format. Expected 'Bearer <token>'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = parts[1]
    claims = await security.verify_clerk_token(token)
    clerk_user_id = claims.get("sub")

    if not clerk_user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token: missing subject claim",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = user_repository.get_by_clerk_id(db, clerk_user_id)
    if not user:
        # Gracefully handle webhook lag by auto-syncing user record from verified token claims
        email = claims.get("email") or f"{clerk_user_id}@clerk.user"
        user = user_repository.upsert_user_from_clerk(
            db=db,
            clerk_user_id=clerk_user_id,
            email=email,
            role="analyst",
        )

    return user


async def require_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Restricts endpoint access strictly to users with the 'admin' role.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required to access this resource",
        )
    return current_user
