from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..adapters import RawResult, ScannerError, get_adapter, sniff_format
from ..auth import require_token
from ..db import get_session, next_refs
from ..models import ApiToken, Finding, Patch, Plan, Project, Scan
from ..schemas import (
    BatchStatus,
    DashboardOut,
    FindingIn,
    FindingOut,
    FindingPage,
    FindingUpdate,
    IdList,
    ImportResult,
    PreviewConfirm,
    PreviewOut,
    ScanOut,
)
from ..scoring import recompute_finding
from ..services import (
    OPEN_STATUSES,
    ImportRejected,
    build_preview,
    confirm_import,
    finding_out,
    guess_project,
    plan_out,
    severity_counts,
    status_counts,
)

router = APIRouter(prefix="/api/findings", tags=["findings"])

SORTABLE = {
    "ref": Finding.ref,
    "severity": Finding.adapted_score,
    "score": Finding.adapted_score,
    "cve_id": Finding.cve_id,
    "status": Finding.status,
    "tool": Finding.tool,
    "created_at": Finding.created_at,
    "updated_at": Finding.updated_at,
}


def _load(session: Session, finding_id: int) -> Finding:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, f"finding {finding_id} not found")
    return finding


def _project(session: Session, project_id: int) -> Project:
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(404, f"project {project_id} not found")
    return project


@router.get("", response_model=FindingPage)
def list_findings(
    project_id: int | None = None,
    severity: str | None = None,
    status: str | None = None,
    tool: str | None = None,
    scan_type: str | None = None,
    reported: bool | None = None,
    has_patch: bool | None = None,
    has_plan: bool | None = None,
    q: str | None = None,
    sort: str = "severity",
    order: str = "desc",
    limit: int = 100,
    offset: int = 0,
    session: Session = Depends(get_session),
):
    query = select(Finding)
    if project_id:
        query = query.where(Finding.project_id == project_id)
    if severity:
        query = query.where(Finding.severity.in_(severity.split(",")))
    if status:
        query = query.where(Finding.status.in_(status.split(",")))
    if tool:
        query = query.where(Finding.tool == tool)
    if scan_type:
        query = query.where(Finding.scan_type == scan_type)
    if reported is not None:
        query = query.where(Finding.reported.is_(reported))
    if has_patch is not None:
        subquery = select(Patch.finding_id)
        query = query.where(Finding.id.in_(subquery) if has_patch else Finding.id.not_in(subquery))
    if has_plan is not None:
        subquery = select(Patch.finding_id).where(Patch.plan_id.is_not(None))
        query = query.where(Finding.id.in_(subquery) if has_plan else Finding.id.not_in(subquery))
    if q:
        pattern = f"%{q.strip()}%"
        query = query.where(
            or_(
                Finding.cve_id.like(pattern),
                Finding.components.like(pattern),
                Finding.title.like(pattern),
                Finding.external_id.like(pattern),
                Finding.ref.like(pattern),
            )
        )

    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    column = SORTABLE.get(sort, Finding.adapted_score)
    query = query.order_by(column.desc().nullslast() if order == "desc" else column.asc().nullsfirst())
    findings = session.scalars(query.limit(min(limit, 500)).offset(offset)).all()

    projects = {project.id: project for project in session.scalars(select(Project)).all()}
    return FindingPage(
        items=[finding_out(finding, projects[finding.project_id]) for finding in findings],
        total=total,
        counts_by_severity=severity_counts(session, project_id),
    )


@router.get("/dashboard", response_model=DashboardOut)
def dashboard(project_id: int | None = None, session: Session = Depends(get_session)):
    projects = {project.id: project for project in session.scalars(select(Project)).all()}
    query = select(Finding)
    if project_id:
        query = query.where(Finding.project_id == project_id)
    findings = session.scalars(query).all()

    rows = [finding_out(finding, projects[finding.project_id]) for finding in findings]
    planned = {
        patch.finding_id
        for patch in session.scalars(select(Patch).where(Patch.plan_id.is_not(None))).all()
    }
    without_plan = sum(
        1 for finding in findings if finding.id not in planned and finding.status in OPEN_STATUSES
    )

    plans_query = select(Plan)
    if project_id:
        plans_query = plans_query.where(Plan.project_id == project_id)
    plans = [plan_out(session, plan) for plan in session.scalars(plans_query).all()]

    scans_query = select(Scan).order_by(Scan.id.desc()).limit(5)
    if project_id:
        scans_query = select(Scan).where(Scan.project_id == project_id).order_by(Scan.id.desc()).limit(5)

    return DashboardOut(
        project_id=project_id,
        by_severity=severity_counts(session, project_id),
        by_status=status_counts(session, project_id),
        total=len(findings),
        without_plan=without_plan,
        overdue_plans=[plan for plan in plans if plan.overdue],
        sla_breaches=sorted(
            [row for row in rows if row.sla_overdue], key=lambda row: -(row.adapted_score or 0)
        )[:25],
        recent_scans=[ScanOut.model_validate(scan) for scan in session.scalars(scans_query).all()],
    )


@router.post("", response_model=FindingOut, status_code=201)
def create_finding(payload: FindingIn, session: Session = Depends(get_session)):
    project = _project(session, payload.project_id)
    finding = Finding(ref=next_refs(session, "findings", 1)[0], **payload.model_dump())
    session.add(finding)
    session.flush()
    recompute_finding(session, finding)
    session.commit()
    return finding_out(finding, project)


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int, session: Session = Depends(get_session)):
    finding = _load(session, finding_id)
    return finding_out(finding, finding.project)


@router.put("/{finding_id}", response_model=FindingOut)
def update_finding(finding_id: int, payload: FindingUpdate, session: Session = Depends(get_session)):
    finding = _load(session, finding_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(finding, field, value)
    recompute_finding(session, finding)
    session.commit()
    return finding_out(finding, finding.project)


@router.delete("/{finding_id}", status_code=204)
def delete_finding(finding_id: int, session: Session = Depends(get_session)):
    session.delete(_load(session, finding_id))
    session.commit()


@router.post("/batch-update", response_model=dict)
def batch_update(payload: BatchStatus, session: Session = Depends(get_session)):
    findings = session.scalars(select(Finding).where(Finding.id.in_(payload.ids))).all()
    for finding in findings:
        if payload.status is not None:
            finding.status = payload.status
        if payload.reported is not None:
            finding.reported = payload.reported
        if payload.severity is not None:
            finding.severity = payload.severity
    session.commit()
    return {"updated": len(findings)}


@router.post("/batch-delete", response_model=dict)
def batch_delete(payload: IdList, session: Session = Depends(get_session)):
    findings = session.scalars(select(Finding).where(Finding.id.in_(payload.ids))).all()
    for finding in findings:
        session.delete(finding)
    session.commit()
    return {"deleted": len(findings)}


@router.post("/preview", response_model=PreviewOut)
async def preview_import(
    project_id: int = Form(...),
    tool: str = Form(""),
    files: list[UploadFile] = File(...),
    session: Session = Depends(get_session),
):
    """Parse one or more result files into the editable preview. Nothing is stored yet."""
    _project(session, project_id)
    parsed = []
    project_ids = []
    warnings = []
    for upload in files:
        content = await upload.read()
        name = upload.filename or "upload"
        try:
            chosen = tool or sniff_format(name, content)
            adapter = get_adapter(chosen)
            findings = adapter.parse(RawResult(payload=content))
        except ScannerError as exc:
            warnings.append(f"{name}: {exc}")
            continue
        target_project = guess_project(session, name, project_id)
        parsed.extend(findings)
        project_ids.extend([target_project] * len(findings))
        warnings.append(f"{name}: {len(findings)} findings parsed with the {chosen} importer")

    if not parsed:
        raise HTTPException(400, "; ".join(warnings) or "no findings could be parsed from the upload")
    return build_preview(session, parsed, project_id, warnings=warnings, project_ids=project_ids)


@router.post("/import", response_model=ImportResult)
def import_preview(payload: PreviewConfirm, session: Session = Depends(get_session)):
    try:
        result = confirm_import(session, payload)
    except ImportRejected as exc:
        raise HTTPException(400, str(exc)) from exc
    session.commit()
    return result


@router.post("/ingest", response_model=ImportResult)
async def ingest(
    origin: str = Form("ci"),
    tool: str = Form(""),
    project_id: int | None = Form(None),
    file: UploadFile = File(...),
    token: ApiToken = Depends(require_token),
    session: Session = Depends(get_session),
):
    """CI push. New rows only, an existing human triage decision is never overwritten."""
    target_project = token.project_id or project_id
    if target_project is None:
        raise HTTPException(400, "this token is not scoped to a project, send project_id with the upload")
    _project(session, target_project)

    content = await file.read()
    name = file.filename or "upload"
    try:
        chosen = tool or sniff_format(name, content)
        findings = get_adapter(chosen).parse(RawResult(payload=content))
    except ScannerError as exc:
        raise HTTPException(400, str(exc)) from exc

    preview = build_preview(session, findings, target_project, warnings=[f"ingested {name}"])
    rows = [row for row in preview["rows"] if row.include]
    if not rows:
        session.commit()
        return ImportResult(created=[], skipped=len(preview["rows"]))
    result = confirm_import(session, PreviewConfirm(rows=rows), origin=origin)
    session.commit()
    return result
