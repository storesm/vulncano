from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..crypto import new_api_token
from ..db import get_session
from ..models import ApiToken
from ..schemas import TokenIn, TokenOut

router = APIRouter(prefix="/api/tokens", tags=["tokens"])


@router.get("", response_model=list[TokenOut])
def list_tokens(session: Session = Depends(get_session)):
    tokens = session.scalars(select(ApiToken).order_by(ApiToken.id.desc())).all()
    return [TokenOut(**{key: getattr(token, key) for key in TokenOut.model_fields if key != "token"})
            for token in tokens]


@router.post("", response_model=TokenOut, status_code=201)
def create_token(payload: TokenIn, session: Session = Depends(get_session)):
    """The plaintext token is shown once, here, and never again."""
    raw, prefix, digest = new_api_token()
    token = ApiToken(name=payload.name, project_id=payload.project_id, prefix=prefix, token_hash=digest)
    session.add(token)
    session.commit()
    return TokenOut(
        id=token.id,
        name=token.name,
        project_id=token.project_id,
        prefix=token.prefix,
        created_at=token.created_at,
        last_used_at=None,
        revoked_at=None,
        token=raw,
    )


@router.delete("/{token_id}", response_model=dict)
def revoke_token(token_id: int, session: Session = Depends(get_session)):
    token = session.get(ApiToken, token_id)
    if token is None:
        raise HTTPException(404, f"token {token_id} not found")
    token.revoked_at = datetime.utcnow()
    session.commit()
    return {"revoked": token.prefix}
