from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters import ADAPTERS, ScanTarget, UploadedFile, get_adapter
from ..crypto import decrypt_config
from ..db import get_session, next_refs
from ..jobs import deserialize_findings, start_scan
from ..models import Project, Scan, ScannerConfig
from ..schemas import PreviewOut, ScanOut
from ..services import build_preview

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _load(session: Session, scan_id: int) -> Scan:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, f"scan {scan_id} not found")
    return scan


@router.get("", response_model=list[ScanOut])
def list_scans(project_id: int | None = None, session: Session = Depends(get_session)):
    query = select(Scan)
    if project_id:
        query = query.where(Scan.project_id == project_id)
    return session.scalars(query.order_by(Scan.id.desc()).limit(100)).all()


@router.post("", response_model=ScanOut, status_code=202)
async def create_scan(
    project_id: int = Form(...),
    tool: str = Form(...),
    scanner_config_id: int | None = Form(None),
    image: str = Form(""),
    path: str = Form(""),
    git_url: str = Form(""),
    files: list[UploadFile] = File(default=[]),
    session: Session = Depends(get_session),
):
    if session.get(Project, project_id) is None:
        raise HTTPException(404, f"project {project_id} not found")
    if tool not in ADAPTERS:
        raise HTTPException(400, f"unknown scanner {tool}. Available: {', '.join(sorted(ADAPTERS))}")

    adapter = get_adapter(tool)
    if not adapter.implemented:
        raise HTTPException(
            501,
            f"The {adapter.label} adapter is under development and cannot run yet. {adapter.install_hint}",
        )

    config = {}
    if scanner_config_id:
        stored = session.get(ScannerConfig, scanner_config_id)
        if stored is None:
            raise HTTPException(404, f"scanner config {scanner_config_id} not found")
        if stored.tool != tool:
            raise HTTPException(400, f"scanner config {stored.name} is for {stored.tool}, not {tool}")
        config = decrypt_config(stored.config_enc)

    uploads = [UploadedFile(name=item.filename or "upload", content=await item.read()) for item in files]
    target = ScanTarget(files=uploads, image=image.strip(), path=path.strip(), git_url=git_url.strip())
    if not (uploads or target.image or target.path or target.git_url):
        raise HTTPException(400, "a scan needs a target: upload a manifest, or give an image, path or git url")

    scan = Scan(
        ref=next_refs(session, "scans", 1)[0],
        project_id=project_id,
        scanner_config_id=scanner_config_id,
        tool=tool,
        source=target.describe()[:500],
        status="queued",
    )
    session.add(scan)
    session.commit()

    start_scan(scan.id, config, target)
    return scan


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, session: Session = Depends(get_session)):
    return _load(session, scan_id)


@router.get("/{scan_id}/log", response_model=dict)
def get_log(scan_id: int, session: Session = Depends(get_session)):
    scan = _load(session, scan_id)
    return {"status": scan.status, "log": scan.log, "error": scan.error, "parsed_count": scan.parsed_count}


@router.get("/{scan_id}/results", response_model=PreviewOut)
def get_results(scan_id: int, session: Session = Depends(get_session)):
    """The preview table for a finished scan. Still nothing written to the archive."""
    scan = _load(session, scan_id)
    if scan.status == "failed":
        raise HTTPException(400, scan.error or "the scan failed, see the log")
    if scan.status not in ("parsed", "imported"):
        raise HTTPException(409, f"scan {scan.ref} is {scan.status}, results are not ready")
    findings = deserialize_findings(scan.parsed_json)
    return build_preview(
        session, findings, scan.project_id, scan_id=scan.id, warnings=scan.log.splitlines()[-10:]
    )


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: int, session: Session = Depends(get_session)):
    session.delete(_load(session, scan_id))
    session.commit()
