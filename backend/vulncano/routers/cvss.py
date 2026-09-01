from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..cvss import CvssError, score_all
from ..db import get_session
from ..models import CVSS_METRICS, CvssFindingOverride, Finding, Project
from ..schemas import CvssConfigIn, CvssOverrideIn, ScoreOut
from ..scoring import (
    NvdError,
    enrich_from_nvd,
    merged_metrics,
    project_config,
    recompute_finding,
    recompute_project,
)

router = APIRouter(prefix="/api/cvss", tags=["cvss"])


@router.get("/project/{project_id}", response_model=CvssConfigIn)
def get_project_metrics(project_id: int, session: Session = Depends(get_session)):
    if session.get(Project, project_id) is None:
        raise HTTPException(404, f"project {project_id} not found")
    config = project_config(session, project_id)
    session.commit()
    return CvssConfigIn(**{name: getattr(config, name) for name in CVSS_METRICS})


@router.put("/project/{project_id}", response_model=dict)
def set_project_metrics(project_id: int, payload: CvssConfigIn, session: Session = Depends(get_session)):
    """Changing a project metric recomputes every finding in that project."""
    if session.get(Project, project_id) is None:
        raise HTTPException(404, f"project {project_id} not found")
    config = project_config(session, project_id)
    for name in CVSS_METRICS:
        setattr(config, name, getattr(payload, name))
    touched = recompute_project(session, project_id)
    session.commit()
    return {"recomputed": touched}


@router.get("/finding/{finding_id}/override", response_model=CvssOverrideIn)
def get_override(finding_id: int, session: Session = Depends(get_session)):
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, f"finding {finding_id} not found")
    override = finding.cvss_override
    return CvssOverrideIn(**{name: getattr(override, name, None) for name in CVSS_METRICS})


@router.put("/finding/{finding_id}/override", response_model=ScoreOut)
def set_override(finding_id: int, payload: CvssOverrideIn, session: Session = Depends(get_session)):
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, f"finding {finding_id} not found")
    override = finding.cvss_override
    if override is None:
        override = CvssFindingOverride(finding_id=finding.id)
        session.add(override)
        session.flush()
        finding.cvss_override = override
    for name in CVSS_METRICS:
        value = getattr(payload, name)
        setattr(override, name, value or None)
    recompute_finding(session, finding)
    session.commit()
    return _score_of(session, finding)


@router.get("/finding/{finding_id}", response_model=ScoreOut)
def get_score(finding_id: int, session: Session = Depends(get_session)):
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, f"finding {finding_id} not found")
    return _score_of(session, finding)


@router.post("/finding/{finding_id}/refresh", response_model=dict)
def refresh_one(finding_id: int, force: bool = False, session: Session = Depends(get_session)):
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, f"finding {finding_id} not found")
    try:
        outcome = enrich_from_nvd(session, finding, force=force)
    except NvdError as exc:
        raise HTTPException(502, str(exc)) from exc
    session.commit()
    return {"result": outcome, "vector": finding.cvss_vector, "base_score": finding.cvss_base_score}


@router.post("/refresh", response_model=dict)
def refresh_many(project_id: int | None = None, force: bool = False, limit: int = 50,
                 session: Session = Depends(get_session)):
    """Bulk NVD refresh. Bounded per call because the public NVD rate limit is low."""
    query = select(Finding).where(Finding.cve_id.is_not(None))
    if project_id:
        query = query.where(Finding.project_id == project_id)
    if not force:
        query = query.where((Finding.cvss_vector == "") | (Finding.cvss_vector.is_(None)))

    updated, failed = 0, []
    for finding in session.scalars(query.limit(limit)).all():
        try:
            if enrich_from_nvd(session, finding, force=force) == "updated":
                updated += 1
        except NvdError as exc:
            failed.append(f"{finding.ref}: {exc}")
    session.commit()
    return {"updated": updated, "failed": failed}


@router.post("/recompute", response_model=dict)
def recompute(project_id: int, session: Session = Depends(get_session)):
    touched = recompute_project(session, project_id)
    session.commit()
    return {"recomputed": touched}


@router.post("/score", response_model=ScoreOut)
def score_vector(payload: dict):
    """Score an arbitrary vector, used by the finding editor to show the effect of a change live."""
    vector = payload.get("vector", "")
    try:
        return score_all(vector, payload.get("metrics") or {})
    except CvssError as exc:
        raise HTTPException(400, str(exc)) from exc


def _score_of(session: Session, finding: Finding) -> ScoreOut:
    if not finding.cvss_vector:
        raise HTTPException(400, f"{finding.ref} has no CVSS vector to score")
    config = project_config(session, finding.project_id)
    try:
        return ScoreOut(**score_all(finding.cvss_vector, merged_metrics(config, finding.cvss_override)))
    except CvssError as exc:
        raise HTTPException(400, str(exc)) from exc
