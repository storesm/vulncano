from datetime import datetime, timedelta

import pytest

from vulncano.adapters import NormalizedFinding
from vulncano.models import Finding, Patch, Plan, Project
from vulncano.schemas import PatchIn, PlanIn, PreviewConfirm
from vulncano.services import (
    ImportRejected,
    build_preview,
    close_plan,
    confirm_import,
    finding_out,
    guess_project,
    plan_out,
    report_blockers,
    sla_state,
)


def sample(cve="CVE-2020-28493", component="jinja2@2.11.2", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):
    return NormalizedFinding(
        title="ReDoS in Jinja2",
        cve_id=cve,
        external_id="GHSA-462w-v97r-4m45",
        components=[component],
        tool="osv",
        cvss_vector=vector,
        fixed_version="2.11.3",
    )


def test_ids_are_assigned_in_order_and_never_recycled(session, project):
    preview = build_preview(session, [sample(), sample(cve="CVE-2020-14343", component="pyyaml@5.3.1")], project.id)
    assert [row.suggested_ref for row in preview["rows"]] == ["VLN-0001", "VLN-0002"]

    result = confirm_import(session, PreviewConfirm(rows=preview["rows"]))
    session.commit()
    assert result["created"] == ["VLN-0001", "VLN-0002"]

    session.delete(session.query(Finding).filter(Finding.ref == "VLN-0002").one())
    session.commit()
    later = build_preview(session, [sample(cve="CVE-2021-44228", component="log4j@2.14.1")], project.id)
    assert later["rows"][0].suggested_ref == "VLN-0003"


def test_skipped_rows_do_not_consume_an_id(session, project):
    rows = [
        sample(cve="CVE-1", component="a@1"),
        sample(cve="CVE-2", component="b@1"),
        sample(cve="CVE-3", component="c@1"),
    ]
    preview = build_preview(session, rows, project.id)
    preview["rows"][1].include = False

    result = confirm_import(session, PreviewConfirm(rows=preview["rows"]))
    session.commit()
    assert result["created"] == ["VLN-0001", "VLN-0002"]
    assert result["skipped"] == 1


def test_duplicates_against_the_archive_are_unticked(session, project):
    first = build_preview(session, [sample()], project.id)
    confirm_import(session, PreviewConfirm(rows=first["rows"]))
    session.commit()

    second = build_preview(session, [sample()], project.id)
    assert second["duplicate_count"] == 1
    assert second["rows"][0].include is False
    assert second["rows"][0].duplicate_of == "VLN-0001"


def test_duplicates_inside_one_batch_are_unticked(session, project):
    preview = build_preview(session, [sample(), sample()], project.id)
    assert preview["duplicate_count"] == 1
    assert [row.include for row in preview["rows"]] == [True, False]


def test_the_same_cve_in_two_projects_is_two_findings(session, project):
    other = Project(key="FRONTEND", name="Frontend")
    session.add(other)
    session.commit()

    first = build_preview(session, [sample()], project.id)
    confirm_import(session, PreviewConfirm(rows=first["rows"]))
    session.commit()

    second = build_preview(session, [sample()], other.id)
    assert second["duplicate_count"] == 0
    assert second["rows"][0].include is True


def test_a_refixed_finding_surfaces_as_a_regression(session, project):
    preview = build_preview(session, [sample()], project.id)
    confirm_import(session, PreviewConfirm(rows=preview["rows"]))
    session.commit()
    stored = session.query(Finding).one()
    stored.status = "Fixed"
    session.commit()

    again = build_preview(session, [sample()], project.id)
    row = again["rows"][0]
    assert row.include is True
    assert row.regression_of == "VLN-0001"

    confirm_import(session, PreviewConfirm(rows=again["rows"]))
    session.commit()
    regression = session.query(Finding).filter(Finding.ref == "VLN-0002").one()
    assert regression.regressed_at is not None
    assert "Re-detected after VLN-0001" in regression.description


def test_severity_comes_from_the_adapted_score(session, project):
    preview = build_preview(session, [sample()], project.id)
    assert preview["rows"][0].severity == "Critical"
    assert preview["rows"][0].cvss_base_score == 9.8


def test_import_can_attach_one_patch_and_one_plan_to_the_whole_batch(session, project):
    rows = build_preview(session, [sample(cve="CVE-1", component="a@1"), sample(cve="CVE-2", component="b@1")], project.id)
    result = confirm_import(
        session,
        PreviewConfirm(
            rows=rows["rows"],
            patch=PatchIn(fixed_version="2.11.3", regression_tests="run the API suite"),
            plan=PlanIn(project_id=project.id, name="March upgrade wave", target_version="4.2"),
        ),
    )
    session.commit()

    assert result["plan_ref"] == "PLAN-0001"
    plan = session.query(Plan).one()
    assert len(session.query(Patch).filter(Patch.plan_id == plan.id).all()) == 2
    assert plan_out(session, plan).finding_count == 2


def test_empty_import_is_rejected(session, project):
    preview = build_preview(session, [sample()], project.id)
    preview["rows"][0].include = False
    with pytest.raises(ImportRejected, match="every row is unticked"):
        confirm_import(session, PreviewConfirm(rows=preview["rows"]))


def test_project_is_taken_from_the_filename_when_it_matches_a_key(session, project):
    other = Project(key="SATVIS", name="Satellite visualiser")
    session.add(other)
    session.commit()
    assert guess_project(session, "SATVIS-requirements.txt", project.id) == other.id
    assert guess_project(session, "requirements.txt", project.id) == project.id


def test_sla_window_and_overdue(session, project):
    project.sla_critical = 7
    finding = Finding(ref="VLN-0001", project_id=project.id, severity="Critical", status="New")
    session.add(finding)
    session.commit()

    allowed, overdue = sla_state(finding, project)
    assert (allowed, overdue) == (7, False)

    finding.created_at = datetime.utcnow() - timedelta(days=9)
    allowed, overdue = sla_state(finding, project)
    assert overdue is True

    finding.status = "Fixed"
    assert sla_state(finding, project)[1] is False


def test_finding_out_reports_the_age_and_the_publication_distance(session, project):
    finding = Finding(
        ref="VLN-0001",
        project_id=project.id,
        severity="High",
        status="Confirmed",
        cve_pub_date=(datetime.utcnow() - timedelta(days=30)).date(),
    )
    session.add(finding)
    session.commit()
    out = finding_out(finding, project)
    assert out.sla_days == project.sla_high
    assert out.days_since_publication == 30


def test_closing_a_plan_fixes_its_findings_and_leaves_accepted_risk_alone(session, project):
    plan = Plan(ref="PLAN-0001", project_id=project.id, name="wave")
    first = Finding(ref="VLN-0001", project_id=project.id, status="Confirmed")
    second = Finding(ref="VLN-0002", project_id=project.id, status="Risk accepted", mitigation="no upstream fix")
    session.add_all([plan, first, second])
    session.flush()
    session.add_all([
        Patch(ref="PATCH-0001", finding_id=first.id, plan_id=plan.id, fixed_version="1.2.3"),
        Patch(ref="PATCH-0002", finding_id=second.id, plan_id=plan.id),
    ])
    session.commit()

    close_plan(session, plan)
    session.commit()
    assert first.status == "Fixed"
    assert first.patch.applied_at is not None
    assert second.status == "Risk accepted"
    assert plan.status == "Done"


def test_plan_lists_what_is_missing(session, project):
    plan = Plan(ref="PLAN-0001", project_id=project.id, name="wave")
    finding = Finding(ref="VLN-0001", project_id=project.id, status="Confirmed")
    session.add_all([plan, finding])
    session.flush()
    session.add(Patch(ref="PATCH-0001", finding_id=finding.id, plan_id=plan.id))
    session.commit()

    missing = plan_out(session, plan).missing
    assert any("no fixed version" in item for item in missing)


def test_report_blockers_name_the_offending_ids(session, project):
    new = Finding(ref="VLN-0001", project_id=project.id, status="New")
    accepted = Finding(ref="VLN-0002", project_id=project.id, status="Risk accepted")
    session.add_all([new, accepted])
    session.commit()

    problems = report_blockers(session, [new, accepted])
    assert any("VLN-0001 is still New" in item for item in problems)
    assert any("VLN-0002 is Risk accepted without a justification" in item for item in problems)
