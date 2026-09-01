"""Fill an empty install with the fixture data so the UI has something to show.

    python scripts/seed_demo.py

Creates two projects, imports three fixture scanner reports, triages part of them and builds
one remediation plan. Safe to run only once, it refuses if the projects already exist.
"""

import sys
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from vulncano.adapters import RawResult, get_adapter, sniff_format  # noqa: E402
from vulncano.db import init_db, next_refs, session_scope  # noqa: E402
from vulncano.models import Patch, Plan, Project  # noqa: E402
from vulncano.schemas import PreviewConfirm  # noqa: E402
from vulncano.services import build_preview, confirm_import  # noqa: E402

FIXTURES = ROOT / "backend" / "fixtures" / "scanners"
SEED = [
    ("BACKEND", "Backend service", ["cyclonedx.json", "dependency-check-report.json"]),
    ("PLATFORM", "Container platform", ["grype.json", "semgrep.sarif"]),
]


def import_file(session, project, name):
    content = (FIXTURES / name).read_bytes()
    findings = get_adapter(sniff_format(name, content)).parse(RawResult(payload=content))
    preview = build_preview(session, findings, project.id)
    result = confirm_import(session, PreviewConfirm(rows=preview["rows"]), origin="demo seed")
    print(f"  {name}: {len(result['created'])} imported, {result['skipped']} duplicates skipped")
    return result["created"]


init_db()
with session_scope() as session:
    if session.query(Project).count():
        raise SystemExit("this install already has projects, seed it on an empty database")

    created_refs = []
    for key, name, files in SEED:
        project = Project(key=key, name=name, description="Demo data from the fixtures directory")
        session.add(project)
        session.flush()
        print(f"{key}")
        for filename in files:
            created_refs.extend(import_file(session, project, filename))

    backend = session.query(Project).filter(Project.key == "BACKEND").one()
    plan = Plan(
        ref=next_refs(session, "plans", 1)[0],
        project_id=backend.id,
        name="Dependency refresh 2.4",
        target_version="2.4.0",
        target_date=date.today() + timedelta(days=21),
        owner="platform team",
        status="In progress",
        notes="Ships with the 2.4 release train.",
    )
    session.add(plan)
    session.flush()

    for finding in backend.findings:
        finding.status = "Confirmed"
        patch = finding.patch
        if patch is None:
            patch = Patch(ref=next_refs(session, "patches", 1)[0], finding_id=finding.id)
            session.add(patch)
        patch.plan_id = plan.id
        patch.regression_tests = "full API suite plus the smoke pipeline"
        patch.schedule = "release 2.4"

    print(f"\nseeded {len(created_refs)} findings and {plan.ref}")
