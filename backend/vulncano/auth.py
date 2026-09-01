"""Optional single user auth plus API tokens for CI. There is no role matrix on purpose."""

import secrets
from datetime import datetime

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .crypto import hash_api_token
from .db import get_session
from .models import ApiToken

basic = HTTPBasic(auto_error=False)


def require_user(credentials: HTTPBasicCredentials | None = Depends(basic)) -> str:
    settings = get_settings()
    if not settings.auth_enabled:
        return "anonymous"
    if credentials is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Basic"},
        )
    user_ok = secrets.compare_digest(credentials.username, settings.auth_user)
    password_ok = secrets.compare_digest(credentials.password, settings.auth_password)
    if not (user_ok and password_ok):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="bad credentials")
    return credentials.username


def require_token(
    authorization: str = Header(default=""),
    session: Session = Depends(get_session),
) -> ApiToken:
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="send an API token as Authorization: Bearer ...")
    raw = authorization.split(" ", 1)[1].strip()
    token = session.scalar(select(ApiToken).where(ApiToken.token_hash == hash_api_token(raw)))
    if token is None or token.revoked_at is not None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="unknown or revoked API token")
    token.last_used_at = datetime.utcnow()
    session.commit()
    return token
