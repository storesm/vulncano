from datetime import datetime

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ..db import get_session
from ..dumping import dump_sql, restore_sql

router = APIRouter(prefix="/api/dump", tags=["dump"])


@router.get("", response_class=PlainTextResponse)
def download_dump(session: Session = Depends(get_session)):
    filename = f"vulncano-{datetime.utcnow():%Y%m%d-%H%M}.sql"
    return PlainTextResponse(
        dump_sql(session),
        media_type="application/sql",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/restore", response_model=dict)
async def upload_dump(file: UploadFile = File(...), session: Session = Depends(get_session)):
    """Replaces the whole database with the dump. Everything currently stored is dropped first."""
    sql = (await file.read()).decode("utf-8", errors="replace")
    try:
        count = restore_sql(session, sql)
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        raise HTTPException(400, f"the dump could not be restored, nothing was changed: {exc}") from exc
    return {"statements": count}
