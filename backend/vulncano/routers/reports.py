import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_session
from ..models import ReportJob
from ..reports import FORMATS, available_templates, mark_reported, start_report
from ..schemas import ReportJobOut, ReportRequest

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _load(session: Session, job_id: int) -> ReportJob:
    job = session.get(ReportJob, job_id)
    if job is None:
        raise HTTPException(404, f"report job {job_id} not found")
    return job


def _to_out(job: ReportJob) -> ReportJobOut:
    return ReportJobOut.model_validate(job).model_copy(
        update={
            "download_url": f"/api/reports/{job.id}/download" if job.output_path else None,
            "bundle_url": f"/api/reports/{job.id}/bundle" if job.bundle_path else None,
        }
    )


@router.get("/templates", response_model=list[dict])
def list_templates():
    return available_templates()


@router.get("", response_model=list[ReportJobOut])
def list_jobs(session: Session = Depends(get_session)):
    jobs = session.scalars(select(ReportJob).order_by(ReportJob.id.desc()).limit(50)).all()
    return [_to_out(job) for job in jobs]


@router.post("/generate", response_model=ReportJobOut, status_code=202)
def generate(payload: ReportRequest, session: Session = Depends(get_session)):
    if payload.output_format not in FORMATS:
        raise HTTPException(400, f"unknown output format, pick one of {', '.join(FORMATS)}")
    params = payload.model_dump()
    if params.get("analysis_date"):
        params["analysis_date"] = params["analysis_date"].isoformat()
    job = ReportJob(
        template=payload.template,
        output_format=payload.output_format,
        params=json.dumps(params),
    )
    session.add(job)
    session.commit()
    start_report(job.id)
    return _to_out(job)


@router.get("/{job_id}", response_model=ReportJobOut)
def get_job(job_id: int, session: Session = Depends(get_session)):
    return _to_out(_load(session, job_id))


@router.get("/{job_id}/download")
def download(job_id: int, session: Session = Depends(get_session)):
    job = _load(session, job_id)
    if job.status != "done" or not job.output_path:
        raise HTTPException(409, job.error or f"report {job_id} is {job.status}")
    path = Path(job.output_path)
    if not path.exists():
        raise HTTPException(410, "the rendered file is gone from the data directory")
    return FileResponse(path, filename=path.name)


@router.get("/{job_id}/bundle")
def download_bundle(job_id: int, session: Session = Depends(get_session)):
    job = _load(session, job_id)
    if not job.bundle_path or not Path(job.bundle_path).exists():
        raise HTTPException(404, "no template bundle was produced for this job")
    return FileResponse(job.bundle_path, filename=Path(job.bundle_path).name)


@router.post("/{job_id}/mark-reported", response_model=dict)
def mark(job_id: int, session: Session = Depends(get_session)):
    job = _load(session, job_id)
    if job.status != "done":
        raise HTTPException(409, "only a finished report can mark its findings as reported")
    count = mark_reported(session, job)
    session.commit()
    return {"marked": count}
