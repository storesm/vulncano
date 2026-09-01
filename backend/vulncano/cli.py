"""Command line front end. Every command goes through the same services the API uses."""

import json
import os
import sys
from pathlib import Path

import click

from .adapters import RawResult, ScanTarget, ScannerError, UploadedFile, get_adapter, sniff_format
from .config import get_settings
from .db import init_db, next_refs, reset_engine, session_scope
from .dumping import dump_sql, restore_sql
from .models import Finding, Plan, Project
from .reports import ReportRejected, render, resolve_scope
from .schemas import PlanIn, PreviewConfirm
from .services import (
    ImportRejected,
    attach_findings_to_plan,
    build_preview,
    confirm_import,
    report_blockers,
)
from .scoring import recompute_project

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _apply_database(url: str | None) -> None:
    if url:
        os.environ["VULNCANO_DATABASE_URL"] = url
        get_settings.cache_clear()
        reset_engine()
    init_db()


def _project_or_die(session, key_or_id: str) -> Project:
    project = session.query(Project).filter(Project.key == str(key_or_id).upper()).one_or_none()
    if project is None and str(key_or_id).isdigit():
        project = session.get(Project, int(key_or_id))
    if project is None:
        raise click.ClickException(f"no project {key_or_id}, create one with: vulncano project create")
    return project


@click.group()
@click.option("--database-url", envvar="VULNCANO_DATABASE_URL", default=None,
              help="SQLAlchemy url, defaults to the sqlite file in VULNCANO_DATA_DIR")
@click.pass_context
def main(ctx, database_url):
    """Vulncano: track and fix software vulnerabilities."""
    ctx.ensure_object(dict)
    _apply_database(database_url)


@main.group()
def project():
    """Create and list projects."""


@project.command("create")
@click.argument("key")
@click.argument("name")
@click.option("--description", default="")
def project_create(key, name, description):
    with session_scope() as session:
        if session.query(Project).filter(Project.key == key.upper()).one_or_none():
            raise click.ClickException(f"project key {key.upper()} already exists")
        item = Project(key=key.upper(), name=name, description=description)
        session.add(item)
        session.flush()
        click.echo(f"{item.key} created (id {item.id})")


@project.command("list")
def project_list():
    with session_scope() as session:
        for item in session.query(Project).order_by(Project.key).all():
            count = session.query(Finding).filter(Finding.project_id == item.id).count()
            click.echo(f"{item.key:12} {item.name:40} {count} findings")


@main.command()
@click.option("--project", "project_key", required=True)
@click.option("--tool", default="osv", help="osv, scanoss, or an importer name")
@click.option("--file", "files", multiple=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--path", default="", help="directory to walk for manifests")
@click.option("--image", default="", help="container image reference")
@click.option("--config", "config_json", default="{}", help="adapter config as JSON")
@click.option("--yes", is_flag=True, help="import without showing the preview")
def scan(project_key, tool, files, path, image, config_json, yes):
    """Run a scanner and import the result."""
    adapter = get_adapter(tool)
    if not adapter.implemented:
        raise click.ClickException(f"the {adapter.label} adapter is under development. {adapter.install_hint}")

    target = ScanTarget(
        files=[UploadedFile(name=Path(item).name, content=Path(item).read_bytes()) for item in files],
        path=path,
        image=image,
    )
    try:
        raw = adapter.run(json.loads(config_json), target)
        findings = adapter.parse(raw)
    except ScannerError as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(raw.log)
    with session_scope() as session:
        item = _project_or_die(session, project_key)
        preview = build_preview(session, findings, item.id)
        _print_preview(preview)
        if not yes and not click.confirm(f"import {sum(1 for row in preview['rows'] if row.include)} findings?"):
            return
        result = confirm_import(session, PreviewConfirm(rows=preview["rows"]))
        click.echo(f"imported {len(result['created'])}: {', '.join(result['created'])}")


@main.command()
@click.argument("result_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--project", "project_key", required=True)
@click.option("--tool", default="", help="force an importer instead of sniffing the format")
@click.option("--origin", default="Manually", help="stamped on the rows, use the CI job id from a pipeline")
@click.option("--yes", is_flag=True)
def ingest(result_file, project_key, tool, origin, yes):
    """Import a scanner output file that already exists."""
    content = Path(result_file).read_bytes()
    try:
        chosen = tool or sniff_format(result_file, content)
        findings = get_adapter(chosen).parse(RawResult(payload=content))
    except ScannerError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"{Path(result_file).name}: {len(findings)} findings parsed with the {chosen} importer")

    with session_scope() as session:
        item = _project_or_die(session, project_key)
        preview = build_preview(session, findings, item.id)
        _print_preview(preview)
        if not yes and not click.confirm("import the ticked rows?"):
            return
        try:
            result = confirm_import(session, PreviewConfirm(rows=preview["rows"]), origin=origin)
        except ImportRejected as exc:
            raise click.ClickException(str(exc)) from exc
        click.echo(f"imported {len(result['created'])}, skipped {result['skipped']}")


@main.command("findings")
@click.option("--project", "project_key", default=None)
@click.option("--severity", default=None)
@click.option("--status", default=None)
@click.option("--limit", default=50)
def list_findings(project_key, severity, status, limit):
    """List findings as a table."""
    with session_scope() as session:
        query = session.query(Finding)
        if project_key:
            query = query.filter(Finding.project_id == _project_or_die(session, project_key).id)
        if severity:
            query = query.filter(Finding.severity.in_(severity.split(",")))
        if status:
            query = query.filter(Finding.status.in_(status.split(",")))
        rows = sorted(query.limit(limit).all(), key=lambda row: SEVERITY_ORDER.get(row.severity, 9))
        for row in rows:
            score = f"{row.adapted_score:.1f}" if row.adapted_score is not None else "  - "
            components = row.components.replace("\n", ", ")[:48]
            click.echo(f"{row.ref}  {row.severity:9} {score:>5}  {(row.cve_id or row.external_id):18} {components}")
        click.echo(f"{len(rows)} findings")


@main.command("plan")
@click.option("--project", "project_key", required=True)
@click.option("--name", required=True)
@click.option("--target-version", default="")
@click.option("--owner", default="")
@click.option("--finding", "finding_refs", multiple=True, help="finding ref, repeatable")
def create_plan(project_key, name, target_version, owner, finding_refs):
    """Create a remediation plan from a list of finding ids."""
    with session_scope() as session:
        item = _project_or_die(session, project_key)
        payload = PlanIn(project_id=item.id, name=name, target_version=target_version, owner=owner)
        plan = Plan(ref=next_refs(session, "plans", 1)[0], **payload.model_dump(exclude={"finding_ids"}))
        session.add(plan)
        session.flush()
        ids = [
            row.id for row in session.query(Finding).filter(Finding.ref.in_(finding_refs)).all()
        ]
        attached = attach_findings_to_plan(session, plan, ids)
        click.echo(f"{plan.ref} created with {attached} findings")


@main.command()
@click.option("--project", "project_key", default=None)
@click.option("--plan", "plan_ref", default=None)
@click.option("--template", default="default")
@click.option("--format", "output_format", default="md", type=click.Choice(["pdf", "html", "md"]))
@click.option("--title", default="Vulnerability report")
@click.option("--out", "output", type=click.Path(dir_okay=False), required=True)
def report(project_key, plan_ref, template, output_format, title, output):
    """Render a report to a file."""
    with session_scope() as session:
        params = {"template": template, "output_format": output_format, "title": title}
        if plan_ref:
            plan = session.query(Plan).filter(Plan.ref == plan_ref.upper()).one_or_none()
            if plan is None:
                raise click.ClickException(f"no plan {plan_ref}")
            params["plan_id"] = plan.id
        elif project_key:
            params["project_id"] = _project_or_die(session, project_key).id
        else:
            raise click.ClickException("give --project or --plan")

        try:
            findings = resolve_scope(session, params)
            blockers = report_blockers(session, findings)
            if blockers:
                raise click.ClickException("not ready to report: " + "; ".join(blockers[:10]))
            content, extension, _ = render(session, findings, params)
        except ReportRejected as exc:
            raise click.ClickException(str(exc)) from exc

        Path(output).write_bytes(content)
        click.echo(f"wrote {output} ({len(findings)} findings, {extension})")


@main.command()
@click.option("--out", "output", type=click.Path(dir_okay=False), default=None)
def dump(output):
    """Dump the whole database as SQL."""
    with session_scope() as session:
        sql = dump_sql(session)
    if output:
        Path(output).write_text(sql)
        click.echo(f"wrote {output}")
    else:
        sys.stdout.write(sql)


@main.command()
@click.argument("dump_file", type=click.Path(exists=True, dir_okay=False))
@click.confirmation_option(prompt="this replaces everything currently stored, continue?")
def restore(dump_file):
    """Restore a dump produced by vulncano dump."""
    with session_scope() as session:
        count = restore_sql(session, Path(dump_file).read_text())
    click.echo(f"restored {count} rows")


@main.command()
@click.option("--project", "project_key", required=True)
def recompute(project_key):
    """Recompute the adapted scores of a project after changing its CVSS metrics."""
    with session_scope() as session:
        item = _project_or_die(session, project_key)
        click.echo(f"recomputed {recompute_project(session, item.id)} findings")


def _print_preview(preview: dict) -> None:
    for row in preview["rows"]:
        mark = "+" if row.include else "-"
        note = f"  ({row.duplicate_reason})" if row.duplicate_reason else ""
        click.echo(
            f" {mark} {row.suggested_ref or '     ':9} {row.severity:9} "
            f"{(row.cve_id or row.external_id or ''):18} {row.components.replace(chr(10), ', ')[:40]}{note}"
        )
    click.echo(f"{preview['duplicate_count']} duplicates skipped")
