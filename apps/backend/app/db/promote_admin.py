import sys
import os

# Ensure apps/backend is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.db.session import SessionLocal
from app.repositories import user_repository


def promote_user_to_admin(email: str):
    """
    Promotes a user account to the 'admin' role in Supabase.
    """
    db = SessionLocal()
    try:
        user = user_repository.get_by_email(db, email.strip())
        if not user:
            print(f"Error: No user found with email '{email}'.")
            print("Please ensure the user has signed up through Clerk first.")
            return False

        updated_user = user_repository.update_role(db, user.id, "admin")
        print(f"Successfully promoted user {updated_user.email} (ID: {updated_user.id}) to role: {updated_user.role}")
        return True
    except Exception as e:
        db.rollback()
        print(f"Failed to promote user: {e}")
        return False
    finally:
        db.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python promote_admin.py <user_email>")
        sys.exit(1)

    target_email = sys.argv[1]
    promote_user_to_admin(target_email)
