"""Report generation. Templates live in a directory and are meant to be replaced, so adding a
layout is dropping a file next to the others, never a backend change."""

import json
import threading
import traceback
import zipfile
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, TemplateNotFound, select_autoescape
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import session_scope
from .models import Finding, Plan, Project, ReportJob
from .services import finding_out, report_blockers

PACKAGE_TEMPLATES = Path(__file__).parent / "templates"
FORMATS = ("pdf", "html", "md")


class ReportRejected(ValueError):
    pass


def template_dirs() -> list[Path]:
    override = get_settings().report_templates_dir
    dirs = [PACKAGE_TEMPLATES]
    if override:
        dirs.insert(0, Path(override))
    return dirs


def available_templates() -> list[dict]:
    seen = {}
    for directory in reversed(template_dirs()):
        if not directory.exists():
            continue
        for path in sorted(directory.glob("*.html")):
            seen[path.stem] = {"name": path.stem, "path": str(path), "formats": list(FORMATS)}
    return list(seen.values())


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader([str(path) for path in template_dirs()]),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def resolve_scope(session: Session, params: dict) -> list[Finding]:
    finding_ids = params.get("finding_ids") or []
    if finding_ids:
        findings = session.scalars(select(Finding).where(Finding.id.in_(finding_ids))).all()
    elif params.get("plan_id"):
        plan = session.get(Plan, params["plan_id"])
        if plan is None:
            raise ReportRejected(f"plan {params['plan_id']} does not exist")
        findings = [patch.finding for patch in plan.patches]
    elif params.get("project_id"):
        findings = session.scalars(
            select(Finding).where(Finding.project_id == params["project_id"])
        ).all()
    else:
        raise ReportRejected("a report needs a scope: a project, a plan or an explicit finding selection")

    if params.get("include_unreported_only"):
        findings = [finding for finding in findings if not finding.reported]
    if not findings:
        raise ReportRejected("the selected scope contains no findings")
    return sorted(findings, key=lambda item: (-(item.adapted_score or 0), item.ref))


def build_context(session: Session, findings: list[Finding], params: dict) -> dict:
    projects = {}
    rows = []
    for finding in findings:
        project = finding.project
        projects[project.id] = project
        rows.append(finding_out(finding, project))

    plan = session.get(Plan, params["plan_id"]) if params.get("plan_id") else None
    remediation = [row for row in rows if row.patch and row.patch.fixed_version]
    accepted = [row for row in rows if row.status == "Risk accepted"]
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    counts = {}
    for row in rows:
        counts[row.severity] = counts.get(row.severity, 0) + 1

    return {
        "title": params.get("title") or "Vulnerability report",
        "document_code": params.get("document_code", ""),
        "version": params.get("version", "1.0"),
        "authors": params.get("authors", ""),
        "software_version": params.get("software_version", ""),
        "analysis_date": params.get("analysis_date") or datetime.utcnow().date().isoformat(),
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "projects": sorted(projects.values(), key=lambda item: item.key),
        "project": next(iter(projects.values())) if len(projects) == 1 else None,
        "findings": sorted(rows, key=lambda row: (severity_order.get(row.severity, 9), row.ref)),
        "remediation": remediation,
        "accepted": accepted,
        "counts": counts,
        "total": len(rows),
    }


def render(session: Session, findings: list[Finding], params: dict) -> tuple[bytes, str, str]:
    """Return (document bytes, file extension, rendered html used for the pdf)."""
    output_format = params.get("output_format", "pdf")
    if output_format not in FORMATS:
        raise ReportRejected(f"unknown output format {output_format}, pick one of {', '.join(FORMATS)}")

    context = build_context(session, findings, params)
    environment = _environment()
    name = params.get("template") or "default"
    suffix = "md" if output_format == "md" else "html"
    try:
        template = environment.get_template(f"{name}.{suffix}")
    except TemplateNotFound as exc:
        raise ReportRejected(
            f"template {name}.{suffix} was not found in {', '.join(str(path) for path in template_dirs())}"
        ) from exc

    rendered = template.render(**context)
    if output_format in ("html", "md"):
        return rendered.encode(), output_format, rendered

    try:
        from weasyprint import HTML
    except ImportError as exc:
        raise ReportRejected(
            "PDF output needs WeasyPrint. Install it with pip install weasyprint, or generate the "
            "report as html or md instead."
        ) from exc
    return HTML(string=rendered).write_pdf(), "pdf", rendered


def bundle_templates(destination: Path, used_template: str) -> Path:
    """Ship the template sources with the output so the document can be reproduced or hand edited."""
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for directory in template_dirs():
            if not directory.exists():
                continue
            for path in directory.glob(f"{used_template}.*"):
                archive.write(path, arcname=path.name)
            for path in directory.glob("*.css"):
                archive.write(path, arcname=path.name)
    return destination


def run_report_job(job_id: int) -> None:
    with session_scope() as session:
        job = session.get(ReportJob, job_id)
        if job is None:
            return
        job.status = "running"
        session.commit()
        params = json.loads(job.params or "{}")
        try:
            findings = resolve_scope(session, params)
            blockers = report_blockers(session, findings)
            if blockers:
                raise ReportRejected(
                    "these findings are not ready to be reported: " + "; ".join(blockers[:20])
                )
            content, extension, _ = render(session, findings, params)
            settings = get_settings()
            output = settings.report_dir / f"report-{job.id:04d}.{extension}"
            output.write_bytes(content)
            job.output_path = str(output)
            job.finding_ids = ",".join(str(finding.id) for finding in findings)
            job.bundle_path = str(
                bundle_templates(settings.report_dir / f"report-{job.id:04d}-templates.zip", job.template)
            )
            job.status = "done"
        except ReportRejected as exc:
            job.status = "failed"
            job.error = str(exc)
        except Exception as exc:
            job.status = "failed"
            job.error = f"{type(exc).__name__}: {exc}"
            traceback.print_exc()
        finally:
            job.finished_at = datetime.utcnow()


def start_report(job_id: int) -> None:
    threading.Thread(target=run_report_job, args=(job_id,), daemon=True).start()


def mark_reported(session: Session, job: ReportJob) -> int:
    ids = [int(item) for item in (job.finding_ids or "").split(",") if item]
    findings = session.scalars(select(Finding).where(Finding.id.in_(ids))).all()
    for finding in findings:
        finding.reported = True
    return len(findings)
