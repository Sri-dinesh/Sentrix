import time
import httpx
from typing import Dict, Any, Optional
from jose import jwt, jwk, JWTError
from fastapi import HTTPException, status
from app.core.config import settings

# JWKS In-memory Cache
_jwks_cache: Dict[str, Any] = {"keys": [], "expires_at": 0}
CACHE_TTL_SECONDS = 3600  # 1 hour


async def get_clerk_jwks() -> Dict[str, Any]:
    """
    Fetches and caches Clerk's JWKS public keys.
    """
    global _jwks_cache
    now = time.time()
    if _jwks_cache["keys"] and now < _jwks_cache["expires_at"]:
        return _jwks_cache

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(settings.CLERK_JWKS_URL)
            response.raise_for_status()
            jwks_data = response.json()
            _jwks_cache = {
                "keys": jwks_data.get("keys", []),
                "expires_at": now + CACHE_TTL_SECONDS,
            }
            return _jwks_cache
    except Exception as e:
        # If network fails but we have stale cache, return it
        if _jwks_cache["keys"]:
            return _jwks_cache
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Unable to fetch Clerk JWKS public keys: {str(e)}",
        )


async def verify_clerk_token(token: str) -> Dict[str, Any]:
    """
    Verifies a Clerk session JWT against Clerk's JWKS public keys.
    Returns the decoded token claims on success.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization token is missing",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # In dev/mock mode or if token is a test token
    if settings.ENVIRONMENT == "development" and token.startswith("test_token_"):
        clerk_id = token.replace("test_token_", "")
        return {"sub": clerk_id, "email": f"{clerk_id}@sentrix.local", "role": "analyst"}

    try:
        unverified_headers = jwt.get_unverified_header(token)
        kid = unverified_headers.get("kid")
        if not kid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token header missing key ID (kid)",
                headers={"WWW-Authenticate": "Bearer"},
            )

        jwks = await get_clerk_jwks()
        target_key = next((k for k in jwks["keys"] if k.get("kid") == kid), None)

        if not target_key:
            # Force cache refresh in case key was recently rotated
            _jwks_cache["expires_at"] = 0
            jwks = await get_clerk_jwks()
            target_key = next((k for k in jwks["keys"] if k.get("kid") == kid), None)

        if not target_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: matching public key not found in JWKS",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Decode and verify token signature and expiration
        payload = jwt.decode(
            token,
            target_key,
            algorithms=["RS256"],
            options={"verify_exp": True, "verify_aud": False},
        )

        if not payload.get("sub"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token payload missing subject (sub) claim",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return payload

    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token verification failed: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication error: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
