import os
import shutil
from typing import Optional
from supabase import create_client, Client
from app.core.config import settings

_supabase_client: Optional[Client] = None


def get_supabase_client() -> Optional[Client]:
    """
    Initializes and caches the Supabase client.
    """
    global _supabase_client
    if _supabase_client is None:
        if (
            settings.SUPABASE_URL
            and settings.SUPABASE_SERVICE_ROLE_KEY
            and settings.SUPABASE_SERVICE_ROLE_KEY != "placeholder_service_role_key"
            and not settings.SUPABASE_SERVICE_ROLE_KEY.startswith("placeholder")
        ):
            try:
                _supabase_client = create_client(
                    settings.SUPABASE_URL, settings.SUPABASE_SERVICE_ROLE_KEY
                )
            except Exception as e:
                print(f"Warning: Failed to initialize Supabase client: {e}")
                _supabase_client = None
    return _supabase_client


def upload_model(
    local_path: str,
    remote_path: str,
    bucket_name: Optional[str] = None,
) -> str:
    """
    Uploads a model checkpoint file to Supabase Storage.
    Falls back to local file storage if remote storage is unreachable in dev mode.
    """
    if not os.path.exists(local_path):
        raise FileNotFoundError(f"Local model file not found: {local_path}")

    bucket = bucket_name or settings.SUPABASE_STORAGE_BUCKET
    client = get_supabase_client()

    if client:
        try:
            with open(local_path, "rb") as f:
                file_bytes = f.read()
            # Upsert into Supabase Storage
            client.storage.from_(bucket).upload(
                path=remote_path,
                file=file_bytes,
                file_options={"upsert": "true"},
            )
            return f"{bucket}/{remote_path}"
        except Exception as e:
            print(f"Supabase Storage upload warning: {e}. Falling back to local path.")

    # Local fallback storage path inside apps/backend/ml/storage
    local_storage_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../ml/storage", bucket)
    )
    dest_path = os.path.join(local_storage_dir, remote_path)
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    shutil.copy2(local_path, dest_path)
    return f"{bucket}/{remote_path}"


def download_model(
    remote_path: str,
    local_path: str,
    bucket_name: Optional[str] = None,
) -> str:
    """
    Downloads a model checkpoint from Supabase Storage to a local file.
    """
    bucket = bucket_name or settings.SUPABASE_STORAGE_BUCKET
    os.makedirs(os.path.dirname(local_path), exist_ok=True)

    client = get_supabase_client()
    if client:
        try:
            clean_remote_path = (
                remote_path.replace(f"{bucket}/", "")
                if remote_path.startswith(f"{bucket}/")
                else remote_path
            )
            data = client.storage.from_(bucket).download(clean_remote_path)
            with open(local_path, "wb") as f:
                f.write(data)
            return local_path
        except Exception as e:
            print(f"Supabase Storage download warning: {e}. Checking local cache.")

    # Check if local fallback copy exists
    clean_remote_path = (
        remote_path.replace(f"{bucket}/", "")
        if remote_path.startswith(f"{bucket}/")
        else remote_path
    )
    local_storage_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../ml/storage", bucket, clean_remote_path)
    )
    if os.path.exists(local_storage_path):
        if local_storage_path != os.path.abspath(local_path):
            shutil.copy2(local_storage_path, local_path)
        return local_path

    # If the local source file itself exists (e.g. apps/backend/ml/models/autoencoder.pt)
    alt_local = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../ml/models", os.path.basename(clean_remote_path))
    )
    if os.path.exists(alt_local):
        if alt_local != os.path.abspath(local_path):
            shutil.copy2(alt_local, local_path)
        return local_path

    raise FileNotFoundError(f"Model checkpoint not found in remote or local storage: {remote_path}")
