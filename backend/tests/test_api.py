"""The flow the README promises, driven through the API exactly as the frontend drives it."""

import time

from conftest import fixture_bytes


def wait_for_job(client, job_id, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/reports/{job_id}").json()
        if job["status"] in ("done", "failed"):
            return job
        time.sleep(0.05)
    raise AssertionError(f"report job {job_id} never finished")


def create_project(client, key="BACKEND"):
    response = client.post("/api/projects", json={"key": key, "name": f"{key} service"})
    assert response.status_code == 201, response.text
    return response.json()


def upload_preview(client, project_id, name="cyclonedx.json"):
    return client.post(
        "/api/findings/preview",
        data={"project_id": project_id},
        files=[("files", (name, fixture_bytes("scanners", name), "application/json"))],
    )


def test_upload_preview_confirm_plan_report(client):
    project = create_project(client)

    preview = upload_preview(client, project["id"])
    assert preview.status_code == 200, preview.text
    body = preview.json()
    assert len(body["rows"]) == 2
    assert [row["suggested_ref"] for row in body["rows"]] == ["VLN-0001", "VLN-0002"]

    confirmed = client.post("/api/findings/import", json={
        "rows": body["rows"],
        "patch": {"fixed_version": "4.17.20", "regression_tests": "npm test"},
        "plan": {"project_id": project["id"], "name": "npm upgrade wave", "target_version": "2.4.0"},
    })
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["created"] == ["VLN-0001", "VLN-0002"]
    assert confirmed.json()["plan_ref"] == "PLAN-0001"

    listed = client.get("/api/findings", params={"project_id": project["id"]}).json()
    assert listed["total"] == 2
    assert listed["items"][0]["plan_name"] == "npm upgrade wave"
    assert listed["items"][0]["adapted_score"] is not None

    plan_id = client.get("/api/plans").json()[0]["id"]
    for finding in listed["items"]:
        client.put(f"/api/findings/{finding['id']}", json={"status": "Confirmed"})

    report = client.post("/api/reports/generate", json={
        "plan_id": plan_id,
        "output_format": "md",
        "title": "Q1 remediation",
        "document_code": "SEC-2026-001",
        "authors": "Security team",
    })
    assert report.status_code == 202, report.text
    job_id = report.json()["id"]

    job = wait_for_job(client, job_id)
    assert job["status"] == "done", job["error"]

    document = client.get(f"/api/reports/{job_id}/download").text
    assert "Q1 remediation" in document
    assert "VLN-0001" in document
    assert "4.17.20" in document

    marked = client.post(f"/api/reports/{job_id}/mark-reported").json()
    assert marked["marked"] == 2
    assert client.get("/api/findings", params={"reported": True}).json()["total"] == 2


def test_second_upload_of_the_same_file_is_all_duplicates(client):
    project = create_project(client)
    first = upload_preview(client, project["id"]).json()
    client.post("/api/findings/import", json={"rows": first["rows"]})

    second = upload_preview(client, project["id"]).json()
    assert second["duplicate_count"] == 2
    assert all(row["include"] is False for row in second["rows"])


def test_report_is_refused_while_triage_is_incomplete(client):
    project = create_project(client)
    preview = upload_preview(client, project["id"]).json()
    client.post("/api/findings/import", json={"rows": preview["rows"]})

    report = client.post("/api/reports/generate", json={"project_id": project["id"], "output_format": "md"})
    job = wait_for_job(client, report.json()["id"])
    assert job["status"] == "failed"
    assert "VLN-0001" in job["error"]
    assert "still New" in job["error"]


def test_project_cvss_metrics_recompute_every_finding(client):
    project = create_project(client)
    preview = upload_preview(client, project["id"]).json()
    client.post("/api/findings/import", json={"rows": preview["rows"]})

    before = client.get("/api/findings").json()["items"]
    scores_before = {row["ref"]: row["adapted_score"] for row in before}

    response = client.put(f"/api/cvss/project/{project['id']}", json={
        "CR": "H", "IR": "H", "AR": "H", "E": "H", "RL": "U", "RC": "C",
        "MAV": "X", "MAC": "X", "MPR": "X", "MUI": "X", "MS": "X", "MC": "X", "MI": "X", "MA": "X",
    })
    assert response.json()["recomputed"] == 2

    after = client.get("/api/findings").json()["items"]
    scores_after = {row["ref"]: row["adapted_score"] for row in after}
    assert all(scores_after[ref] > scores_before[ref] for ref in scores_before)
    assert all("CR:H" in row["adapted_vector"] for row in after)


def test_finding_override_beats_the_project_selection(client):
    project = create_project(client)
    preview = upload_preview(client, project["id"]).json()
    client.post("/api/findings/import", json={"rows": preview["rows"]})
    finding = client.get("/api/findings").json()["items"][0]

    client.put(f"/api/cvss/project/{project['id']}", json={"CR": "H"})
    client.put(f"/api/cvss/finding/{finding['id']}/override", json={"CR": "L"})

    scored = client.get(f"/api/cvss/finding/{finding['id']}").json()
    assert "CR:L" in scored["vector"]


def test_manual_crud_and_bulk_actions(client):
    project = create_project(client)
    created = client.post("/api/findings", json={
        "project_id": project["id"],
        "title": "Hardcoded credential in the deploy script",
        "severity": "High",
        "scan_type": "secret",
        "components": "deploy/release.sh",
        "status": "Confirmed",
    })
    assert created.status_code == 201, created.text
    finding = created.json()
    assert finding["ref"] == "VLN-0001"

    updated = client.put(f"/api/findings/{finding['id']}", json={"status": "Risk accepted", "mitigation": "rotated"})
    assert updated.json()["status"] == "Risk accepted"

    bulk = client.post("/api/findings/batch-update", json={"ids": [finding["id"]], "reported": True})
    assert bulk.json()["updated"] == 1

    assert client.post("/api/findings/batch-delete", json={"ids": [finding["id"]]}).json()["deleted"] == 1
    assert client.get("/api/findings").json()["total"] == 0


def test_stubbed_adapter_answers_501_with_the_reason(client):
    project = create_project(client)
    response = client.post(
        "/api/scans",
        data={"project_id": project["id"], "tool": "trivy", "path": "/tmp"},
    )
    assert response.status_code == 501
    assert "under development" in response.json()["detail"]


def test_scan_needs_a_target(client):
    project = create_project(client)
    response = client.post("/api/scans", data={"project_id": project["id"], "tool": "osv"})
    assert response.status_code == 400
    assert "needs a target" in response.json()["detail"]


def test_adapters_endpoint_drives_the_settings_form(client):
    adapters = {item["tool"]: item for item in client.get("/api/scanners/adapters").json()}
    assert adapters["osv"]["implemented"] is True
    assert adapters["trivy"]["implemented"] is False
    assert "api_key" in adapters["scanoss"]["secret_fields"]
    assert "binary_path" in adapters["trivy"]["schema"]["properties"]


def test_scanner_secrets_never_come_back_from_the_api(client):
    created = client.post("/api/scanners/configs", json={
        "tool": "scanoss",
        "name": "public endpoint",
        "config": {"api_url": "https://api.osskb.org", "api_key": "super-secret"},
    })
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["credential_set"] is True
    assert "api_key" not in body["config"]
    assert body["config"]["api_url"] == "https://api.osskb.org"

    listed = client.get("/api/scanners/configs").json()
    assert "super-secret" not in str(listed)


def test_ci_ingest_with_a_token(client):
    project = create_project(client)
    token = client.post("/api/tokens", json={"name": "jenkins", "project_id": project["id"]}).json()
    assert token["token"].startswith("vlc_")

    response = client.post(
        "/api/findings/ingest",
        data={"origin": "jenkins/backend-nightly#412"},
        files=[("file", ("grype.json", fixture_bytes("scanners", "grype.json"), "application/json"))],
        headers={"Authorization": f"Bearer {token['token']}"},
    )
    assert response.status_code == 200, response.text
    assert len(response.json()["created"]) == 2

    rows = client.get("/api/findings").json()["items"]
    assert all(row["origin"] == "jenkins/backend-nightly#412" for row in rows)
    assert all(row["status"] == "New" for row in rows)


def test_ingest_refuses_an_unknown_token(client):
    response = client.post(
        "/api/findings/ingest",
        files=[("file", ("grype.json", b"{}", "application/json"))],
        headers={"Authorization": "Bearer nope"},
    )
    assert response.status_code == 401


def test_dashboard_counts(client):
    project = create_project(client)
    preview = upload_preview(client, project["id"]).json()
    client.post("/api/findings/import", json={"rows": preview["rows"]})

    dashboard = client.get("/api/findings/dashboard", params={"project_id": project["id"]}).json()
    assert dashboard["total"] == 2
    assert dashboard["without_plan"] == 2
    assert sum(dashboard["by_severity"].values()) == 2


def test_dump_and_restore_round_trip(client):
    project = create_project(client)
    preview = upload_preview(client, project["id"]).json()
    client.post("/api/findings/import", json={"rows": preview["rows"]})

    dump = client.get("/api/dump").text
    assert "INSERT INTO findings" in dump

    client.post("/api/findings/batch-delete", json={
        "ids": [row["id"] for row in client.get("/api/findings").json()["items"]]
    })
    assert client.get("/api/findings").json()["total"] == 0

    restored = client.post("/api/dump/restore", files=[("file", ("dump.sql", dump.encode(), "application/sql"))])
    assert restored.status_code == 200, restored.text
    assert client.get("/api/findings").json()["total"] == 2


def test_merging_four_manifests_routes_rows_by_filename(client):
    backend = create_project(client, "BACKEND")
    frontend = create_project(client, "FRONTEND")

    response = client.post(
        "/api/findings/preview",
        data={"project_id": backend["id"]},
        files=[
            ("files", ("BACKEND-grype.json", fixture_bytes("scanners", "grype.json"), "application/json")),
            ("files", ("FRONTEND-cyclonedx.json", fixture_bytes("scanners", "cyclonedx.json"), "application/json")),
        ],
    )
    assert response.status_code == 200, response.text
    rows = response.json()["rows"]
    assert {row["project_id"] for row in rows} == {backend["id"], frontend["id"]}
    assert [row["suggested_ref"] for row in rows] == ["VLN-0001", "VLN-0002", "VLN-0003", "VLN-0004"]
