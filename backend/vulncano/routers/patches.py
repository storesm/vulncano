from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_session, next_refs
from ..models import Finding, Patch
from ..schemas import PatchIn, PatchOut

router = APIRouter(prefix="/api/patches", tags=["patches"])


@router.get("", response_model=list[PatchOut])
def list_patches(plan_id: int | None = None, session: Session = Depends(get_session)):
    query = select(Patch)
    if plan_id:
        query = query.where(Patch.plan_id == plan_id)
    return session.scalars(query.order_by(Patch.id)).all()


@router.put("/finding/{finding_id}", response_model=PatchOut)
def upsert_patch(finding_id: int, payload: PatchIn, session: Session = Depends(get_session)):
    """One finding has at most one patch, so the fix is created or updated in the same call."""
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, f"finding {finding_id} not found")
    patch = finding.patch
    if patch is None:
        patch = Patch(ref=next_refs(session, "patches", 1)[0], finding_id=finding.id)
        session.add(patch)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(patch, field, value)
    session.commit()
    return patch


@router.delete("/{patch_id}", status_code=204)
def delete_patch(patch_id: int, session: Session = Depends(get_session)):
    patch = session.get(Patch, patch_id)
    if patch is None:
        raise HTTPException(404, f"patch {patch_id} not found")
    session.delete(patch)
    session.commit()
