"""Everything that happens between a parsed scanner result and a stored finding: deduplication,
the preview table, the confirmed import, ageing and the dashboard aggregates.

The API and the CLI both call these functions, there is no second implementation anywhere.
"""

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .adapters import NormalizedFinding
from .cvss import CvssError, score_all
from .db import next_refs, peek_refs
from .models import (
    SEVERITIES,
    Counter,
    Finding,
    Patch,
    Plan,
    Project,
    Scan,
)
from .schemas import FindingOut, PatchOut, PlanOut, PreviewConfirm, PreviewRow
from .scoring import merged_metrics, project_config, recompute_finding

OPEN_STATUSES = ("New", "Confirmed")
CLOSED_STATUSES = ("Fixed", "False positive", "Risk accepted")


class ImportRejected(ValueError):
    """Raised when an import cannot proceed, carrying a message naming what is wrong."""


def dedup_key(project_id: int, identifier: str, components: str) -> tuple:
    """The same CVE on the same component in the same project. Two projects, two findings."""
    parts = tuple(sorted(line.strip().lower() for line in components.splitlines() if line.strip()))
    return project_id, (identifier or "").strip().lower(), parts


def existing_keys(session: Session) -> dict[tuple, Finding]:
    index = {}
    for finding in session.scalars(select(Finding)).all():
        identifier = finding.cve_id or finding.external_id or finding.title
        index[dedup_key(finding.project_id, identifier, finding.components)] = finding
    return index


def project_by_key(session: Session, key: str) -> Project | None:
    return session.scalar(select(Project).where(Project.key == key.upper()))


def guess_project(session: Session, filename: str, default_id: int) -> int:
    """Four manifests from four repositories: take the project from the filename when it matches a key."""
    stem = filename.replace("\\", "/").split("/")[-1].upper()
    for project in session.scalars(select(Project)).all():
        if project.key and project.key in stem:
            return project.id
    return default_id


def build_preview(
    session: Session,
    findings: list[NormalizedFinding],
    project_id: int,
    scan_id: int | None = None,
    warnings: list[str] | None = None,
    project_ids: list[int] | None = None,
) -> dict:
    """Turn parsed findings into an editable table. Nothing is written until confirm_import."""
    stored = existing_keys(session)
    batch_seen: dict[tuple, PreviewRow] = {}
    rows: list[PreviewRow] = []
    duplicates = 0

    for index, item in enumerate(findings):
        target_project = (project_ids or [])[index] if project_ids and index < len(project_ids) else project_id
        components = "\n".join(item.components)
        identifier = item.cve_id or item.external_id or item.title
        key = dedup_key(target_project, identifier, components)

        row = PreviewRow(
            project_id=target_project,
            cve_id=item.cve_id,
            external_id=item.external_id,
            title=item.title,
            description=item.description,
            cve_pub_date=item.cve_pub_date,
            severity=item.severity,
            components=components,
            scan_type=item.scan_type,
            tool=item.tool,
            mitigation=item.mitigation,
            file_path=item.file_path,
            line=item.line,
            cvss_vector=item.cvss_vector,
            cvss_base_score=item.cvss_base_score,
            fixed_version=item.fixed_version,
        )

        if item.cvss_vector:
            config = project_config(session, target_project)
            try:
                scores = score_all(item.cvss_vector, merged_metrics(config, None))
                row.cvss_base_score = scores["base_score"]
                row.adapted_score = scores["adapted_score"]
                row.severity = scores["adapted_severity"]
            except CvssError:
                row.cvss_vector = ""

        previous = stored.get(key)
        if previous is not None and previous.status == "Fixed":
            row.regression_of = previous.ref
            row.duplicate_reason = f"re-detected after {previous.ref} was marked Fixed"
        elif previous is not None:
            row.include = False
            row.duplicate_of = previous.ref
            row.duplicate_reason = f"already stored as {previous.ref}"
            duplicates += 1
        elif key in batch_seen:
            row.include = False
            row.duplicate_of = "batch"
            row.duplicate_reason = "the same advisory and component appears twice in this batch"
            duplicates += 1
        else:
            batch_seen[key] = row

        rows.append(row)

    reflow_refs(session, rows)
    counter = session.scalar(select(Counter.value).where(Counter.name == "findings")) or 0
    return {
        "scan_id": scan_id,
        "rows": rows,
        "warnings": warnings or [],
        "duplicate_count": duplicates,
        "next_number": counter + 1,
    }


def reflow_refs(session: Session, rows: list[PreviewRow]) -> None:
    """Suggested ids follow the ticked rows, so a skipped row leaves no hole in the numbering."""
    included = [row for row in rows if row.include]
    suggestions = peek_refs(session, "findings", len(included))
    for row, ref in zip(included, suggestions):
        row.suggested_ref = ref
    for row in rows:
        if not row.include:
            row.suggested_ref = ""


def confirm_import(session: Session, payload: PreviewConfirm, origin: str = "Manually") -> dict:
    """Insert the ticked rows, optionally attaching one patch and one plan to the whole batch."""
    included = [row for row in payload.rows if row.include]
    if not included:
        raise ImportRejected("nothing to import, every row is unticked")

    projects = {project.id: project for project in session.scalars(select(Project)).all()}
    unknown = sorted({row.project_id for row in included if row.project_id not in projects})
    if unknown:
        raise ImportRejected(f"unknown project ids in the batch: {', '.join(str(item) for item in unknown)}")

    plan = None
    if payload.plan_id:
        plan = session.get(Plan, payload.plan_id)
        if plan is None:
            raise ImportRejected(f"plan {payload.plan_id} does not exist")
    elif payload.plan is not None:
        plan_refs = next_refs(session, "plans", 1)
        plan = Plan(
            ref=plan_refs[0],
            project_id=payload.plan.project_id,
            name=payload.plan.name,
            target_version=payload.plan.target_version,
            target_date=payload.plan.target_date,
            owner=payload.plan.owner,
            status=payload.plan.status,
            notes=payload.plan.notes,
        )
        session.add(plan)
        session.flush()

    refs = next_refs(session, "findings", len(included))
    patch_refs = next_refs(session, "patches", len(included)) if payload.patch is not None else []
    created = []

    for position, row in enumerate(included):
        finding = Finding(
            ref=refs[position],
            project_id=row.project_id,
            cve_id=row.cve_id,
            external_id=row.external_id,
            title=row.title[:500],
            description=row.description,
            cve_pub_date=row.cve_pub_date,
            severity=row.severity,
            components=row.components,
            scan_type=row.scan_type,
            tool=row.tool,
            origin=origin,
            status=row.status,
            mitigation=row.mitigation,
            file_path=row.file_path,
            line=row.line,
            cvss_vector=row.cvss_vector,
            cvss_base_score=row.cvss_base_score,
            cvss_source=row.tool if row.cvss_vector else "",
            cvss_fetched_at=datetime.utcnow() if row.cvss_vector else None,
            scan_id=payload.scan_id,
        )
        if row.regression_of:
            finding.regressed_at = datetime.utcnow()
            finding.description = (
                f"Re-detected after {row.regression_of} was closed as Fixed.\n\n{finding.description}"
            )
        session.add(finding)
        session.flush()
        recompute_finding(session, finding)

        if payload.patch is not None or row.fixed_version or plan is not None:
            source = payload.patch
            patch = Patch(
                ref=patch_refs[position] if patch_refs else next_refs(session, "patches", 1)[0],
                finding_id=finding.id,
                plan_id=plan.id if plan else (source.plan_id if source else None),
                fixed_version=(source.fixed_version if source and source.fixed_version else row.fixed_version),
                patch_pub_date=source.patch_pub_date if source else None,
                functional_impact=source.functional_impact if source else "",
                operational_impact=source.operational_impact if source else "",
                regression_tests=source.regression_tests if source else "",
                schedule=source.schedule if source else "",
                comments=source.comments if source else "",
            )
            session.add(patch)

        created.append(finding.ref)

    if payload.scan_id:
        scan = session.get(Scan, payload.scan_id)
        if scan is not None:
            scan.status = "imported"
            scan.imported_count = len(created)

    session.flush()
    return {"created": created, "skipped": len(payload.rows) - len(included), "plan_ref": plan.ref if plan else None}


def age_days(finding: Finding) -> int:
    return max((datetime.utcnow() - finding.created_at).days, 0)


def sla_state(finding: Finding, project: Project) -> tuple[int, bool]:
    allowed = project.sla_days(finding.severity)
    if finding.status in CLOSED_STATUSES:
        return allowed, False
    return allowed, age_days(finding) > allowed


def finding_out(finding: Finding, project: Project) -> FindingOut:
    allowed, overdue = sla_state(finding, project)
    patch = finding.patch
    since_publication = None
    if finding.cve_pub_date:
        since_publication = (datetime.utcnow().date() - finding.cve_pub_date).days
    return FindingOut(
        **{
            column.name: getattr(finding, column.name)
            for column in Finding.__table__.columns
            if column.name in FindingOut.model_fields
        },
        project_key=project.key,
        patch=PatchOut.model_validate(patch) if patch else None,
        plan_id=patch.plan_id if patch else None,
        plan_name=patch.plan.name if patch and patch.plan else "",
        age_days=age_days(finding),
        sla_days=allowed,
        sla_overdue=overdue,
        days_since_publication=since_publication,
    )


def plan_out(session: Session, plan: Plan) -> PlanOut:
    patches = session.scalars(select(Patch).where(Patch.plan_id == plan.id)).all()
    findings = {patch.finding_id: patch.finding for patch in patches}
    missing = []
    for patch in patches:
        if not patch.fixed_version and patch.finding.status != "Risk accepted":
            missing.append(f"{patch.finding.ref} has no fixed version")
        if patch.fixed_version and not patch.regression_tests:
            missing.append(f"{patch.finding.ref} has no regression test defined")
    fixed = sum(1 for finding in findings.values() if finding.status == "Fixed")
    overdue = bool(
        plan.target_date
        and plan.status not in ("Done", "Cancelled")
        and plan.target_date < datetime.utcnow().date()
    )
    return PlanOut(
        **{column.name: getattr(plan, column.name) for column in Plan.__table__.columns},
        finding_count=len(patches),
        fixed_count=fixed,
        overdue=overdue,
        missing=missing,
    )


def close_plan(session: Session, plan: Plan) -> int:
    """Marking a plan Done fixes its findings and stamps applied_at on their patches."""
    patches = session.scalars(select(Patch).where(Patch.plan_id == plan.id)).all()
    today = datetime.utcnow().date()
    touched = 0
    for patch in patches:
        finding = patch.finding
        if finding.status == "Risk accepted":
            continue
        finding.status = "Fixed"
        patch.applied_at = patch.applied_at or today
        touched += 1
    plan.status = "Done"
    return touched


def attach_findings_to_plan(session: Session, plan: Plan, finding_ids: list[int]) -> int:
    """Selecting rows and creating a plan is one action, so missing patch records are created here."""
    attached = 0
    for finding_id in finding_ids:
        finding = session.get(Finding, finding_id)
        if finding is None:
            continue
        patch = finding.patch
        if patch is None:
            patch = Patch(ref=next_refs(session, "patches", 1)[0], finding_id=finding.id)
            session.add(patch)
        patch.plan_id = plan.id
        attached += 1
    session.flush()
    return attached


def severity_counts(session: Session, project_id: int | None = None) -> dict[str, int]:
    query = select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
    if project_id:
        query = query.where(Finding.project_id == project_id)
    counts = dict(session.execute(query).all())
    return {severity: counts.get(severity, 0) for severity in SEVERITIES}


def status_counts(session: Session, project_id: int | None = None) -> dict[str, int]:
    query = select(Finding.status, func.count(Finding.id)).group_by(Finding.status)
    if project_id:
        query = query.where(Finding.project_id == project_id)
    return dict(session.execute(query).all())


def report_blockers(session: Session, findings: list[Finding]) -> list[str]:
    """A report only goes out when the remediation story is complete enough to print."""
    problems = []
    for finding in findings:
        patch = finding.patch
        if finding.status in ("New",):
            problems.append(f"{finding.ref} is still New, triage it first")
            continue
        if finding.status == "Risk accepted" and not finding.mitigation:
            problems.append(f"{finding.ref} is Risk accepted without a justification in the mitigation field")
            continue
        if finding.status == "False positive":
            continue
        if patch is None or (not patch.fixed_version and not finding.mitigation):
            problems.append(f"{finding.ref} has neither a fixed version nor a mitigation")
    return problems
