import uuid
from typing import Optional, List
from sqlalchemy.orm import Session
from app.models.user import User


def get_by_id(db: Session, user_id: uuid.UUID) -> Optional[User]:
    """Retrieve a user by internal UUID."""
    return db.query(User).filter(User.id == user_id).first()


def get_by_clerk_id(db: Session, clerk_user_id: str) -> Optional[User]:
    """Retrieve a user by Clerk User ID."""
    return db.query(User).filter(User.clerk_user_id == clerk_user_id).first()


def get_by_email(db: Session, email: str) -> Optional[User]:
    """Retrieve a user by email address."""
    return db.query(User).filter(User.email == email).first()


def create_user(
    db: Session,
    clerk_user_id: str,
    email: str,
    role: str = "analyst",
) -> User:
    """Create a new user synchronized from Clerk."""
    user = User(
        clerk_user_id=clerk_user_id,
        email=email,
        role=role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def upsert_user_from_clerk(
    db: Session,
    clerk_user_id: str,
    email: str,
    role: str = "analyst",
) -> User:
    """Upserts a user upon Clerk webhook or authentication event."""
    user = get_by_clerk_id(db, clerk_user_id)
    if user:
        if user.email != email:
            user.email = email
            db.commit()
            db.refresh(user)
        return user
    return create_user(db, clerk_user_id, email, role)


def update_role(db: Session, user_id: uuid.UUID, new_role: str) -> Optional[User]:
    """Update a user's role (e.g. analyst -> admin)."""
    user = get_by_id(db, user_id)
    if not user:
        return None
    user.role = new_role
    db.commit()
    db.refresh(user)
    return user


def list_users(db: Session, limit: int = 50, offset: int = 0) -> List[User]:
    """List users with pagination."""
    return db.query(User).offset(offset).limit(limit).all()
