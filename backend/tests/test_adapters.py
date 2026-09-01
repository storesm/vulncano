"""Parse steps run for real against the fixtures. Run steps use a stubbed transport."""

import json

import httpx
import pytest
from conftest import fixture_bytes, fixture_text

from vulncano.adapters import RawResult, ScanTarget, ScannerError, UploadedFile, get_adapter, sniff_format
from vulncano.adapters.checkmarx import CheckmarxAdapter
from vulncano.adapters.osv import OsvAdapter
from vulncano.adapters.scanoss import ScanossAdapter
from vulncano.adapters.trivy import TrivyAdapter
from vulncano.adapters.base import NotImplementedYet


def raw(*parts) -> RawResult:
    return RawResult(payload=fixture_bytes(*parts))


def test_osv_parse_resolves_aliases_and_fixed_versions():
    findings = OsvAdapter().parse(raw("scanners", "osv-resolved.json"))
    assert len(findings) == 3
    jinja = next(item for item in findings if "jinja2@2.11.2" in item.components)
    assert jinja.cve_id == "CVE-2020-28493"
    assert jinja.external_id == "GHSA-462w-v97r-4m45"
    assert jinja.fixed_version == "2.11.3"
    assert jinja.cvss_vector.startswith("CVSS:3.1/")
    assert jinja.cve_pub_date.isoformat() == "2021-02-01"

    flask = next(item for item in findings if item.external_id == "CVE-2023-30861")
    assert flask.cve_id == "CVE-2023-30861"
    assert flask.components == ["flask@2.0.1"]


def test_osv_run_queries_in_batches_and_keeps_one_row_per_advisory(monkeypatch):
    """The tool is stubbed, only the request shape and the merge behaviour are checked."""
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/querybatch"):
            queries = json.loads(request.content)["queries"]
            seen["queries"] = queries
            results = []
            for query in queries:
                if query["package"]["name"].lower() in ("jinja2", "pyyaml"):
                    # OSV answers with the advisory and its CVE alias as two separate ids
                    results.append({"vulns": [{"id": "GHSA-462w-v97r-4m45"}, {"id": "CVE-2020-28493"}]})
                else:
                    results.append({})
            return httpx.Response(200, json={"results": results})
        seen["details"] = seen.get("details", 0) + 1
        return httpx.Response(200, json={
            "id": "GHSA-462w-v97r-4m45",
            "aliases": ["CVE-2020-28493"],
            "summary": "ReDoS in Jinja2",
            "affected": [{"package": {"name": "jinja2", "ecosystem": "PyPI"},
                          "ranges": [{"events": [{"fixed": "2.11.3"}]}]}],
        })

    transport = httpx.MockTransport(handler)
    original = httpx.Client
    monkeypatch.setattr(
        httpx, "Client", lambda **kwargs: original(**{**kwargs, "transport": transport})
    )

    target = ScanTarget(files=[UploadedFile("requirements.txt", fixture_bytes("manifests", "requirements.txt"))])
    result = OsvAdapter().run({}, target)
    findings = OsvAdapter().parse(result)

    assert {query["package"]["name"] for query in seen["queries"]} >= {"Flask", "Jinja2", "PyYAML"}
    assert seen["details"] == 1
    assert len(findings) == 1
    assert sorted(findings[0].components) == ["Jinja2@2.11.2", "PyYAML@5.3.1"]


def test_osv_run_without_dependencies_says_so():
    with pytest.raises(ScannerError, match="no dependencies"):
        OsvAdapter().run({}, ScanTarget(files=[UploadedFile("notes.txt", b"hello")]))


def test_scanoss_parse_reads_both_shapes():
    findings = ScanossAdapter().parse(raw("scanners", "scanoss-dependencies.json"))
    assert len(findings) == 3
    log4j = next(item for item in findings if item.cve_id == "CVE-2021-44228")
    assert log4j.components == ["log4j-core@2.14.1"]
    assert log4j.severity == "Critical"
    assert log4j.cvss_base_score == 10.0

    jinja = next(item for item in findings if item.cve_id == "CVE-2020-28493")
    assert jinja.components == ["jinja2@2.11.2"]
    assert jinja.fixed_version == "2.11.3"


def test_scanoss_run_sends_purls(monkeypatch):
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured["url"] = url
        captured["purls"] = [entry["purl"] for entry in json["files"][0]["purls"]]
        return httpx.Response(200, json={"files": []}, request=httpx.Request("POST", url))

    monkeypatch.setattr("vulncano.adapters.scanoss.httpx.post", fake_post)
    target = ScanTarget(files=[UploadedFile("pom.xml", fixture_bytes("manifests", "pom.xml"))])
    ScanossAdapter().run({}, target)

    assert captured["url"].endswith("/api/dependencies")
    assert "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" in captured["purls"]


def test_scanoss_reports_a_rejected_key(monkeypatch):
    def fake_post(url, json=None, headers=None, timeout=None):
        request = httpx.Request("POST", url)
        return httpx.Response(403, text="forbidden", request=request)

    monkeypatch.setattr("vulncano.adapters.scanoss.httpx.post", fake_post)
    target = ScanTarget(files=[UploadedFile("pom.xml", fixture_bytes("manifests", "pom.xml"))])
    with pytest.raises(ScannerError, match="key in the scanner settings was rejected"):
        ScanossAdapter().run({"api_key": "wrong"}, target)


def test_sarif_import():
    findings = get_adapter("sarif").parse(raw("scanners", "semgrep.sarif"))
    assert len(findings) == 2
    xss = next(item for item in findings if item.file_path == "app/views.py")
    assert xss.severity == "High"
    assert xss.line == 118
    assert xss.external_id == "CWE-79"
    assert xss.scan_type == "static"
    assert xss.tool == "semgrep"


def test_cyclonedx_import_resolves_affects_refs():
    findings = get_adapter("cyclonedx").parse(raw("scanners", "cyclonedx.json"))
    assert len(findings) == 2
    lodash = next(item for item in findings if item.cve_id == "CVE-2020-8203")
    assert lodash.components == ["lodash@4.17.15"]
    assert lodash.cvss_base_score == 7.4
    assert lodash.mitigation == "Upgrade to 4.17.20"


def test_cyclonedx_without_vulnerabilities_is_rejected():
    payload = json.dumps({"bomFormat": "CycloneDX", "components": []}).encode()
    with pytest.raises(ScannerError, match="no vulnerabilities section"):
        get_adapter("cyclonedx").parse(RawResult(payload=payload))


def test_grype_import_uses_related_vulnerabilities():
    findings = get_adapter("grype").parse(raw("scanners", "grype.json"))
    assert len(findings) == 2
    openssl = next(item for item in findings if item.components == ["openssl@1.1.1k-1"])
    assert openssl.scan_type == "container"
    assert openssl.fixed_version == "1.1.1k-1+deb11u1"

    py = next(item for item in findings if item.external_id == "GHSA-w596-4wvx-j9j6")
    assert py.cve_id == "CVE-2022-42969"
    assert py.cvss_base_score == 7.5


def test_dependency_check_import_builds_the_vector_from_the_metrics():
    findings = get_adapter("dependency-check").parse(raw("scanners", "dependency-check-report.json"))
    assert len(findings) == 2
    log4j = next(item for item in findings if item.cve_id == "CVE-2021-44228")
    assert log4j.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert log4j.components == ["log4j-core@2.14.1"]
    assert "CWE-502" in log4j.external_id


def test_spreadsheet_import():
    findings = get_adapter("spreadsheet").parse(raw("scanners", "security-team.csv"))
    assert len(findings) == 3
    spring = next(item for item in findings if item.cve_id == "CVE-2022-22965")
    assert spring.components == ["spring-beans@5.3.15"]
    assert spring.cvss_base_score == 9.8
    assert spring.fixed_version == "Upgrade to 5.3.18"


def test_spreadsheet_without_a_usable_column_says_what_is_expected():
    with pytest.raises(ScannerError, match="CVE or a PACKAGE column"):
        get_adapter("spreadsheet").parse(RawResult(payload=b"foo,bar\n1,2\n"))


@pytest.mark.parametrize(
    "name,expected",
    [
        ("semgrep.sarif", "sarif"),
        ("cyclonedx.json", "cyclonedx"),
        ("grype.json", "grype"),
        ("dependency-check-report.json", "dependency-check"),
        ("security-team.csv", "spreadsheet"),
    ],
)
def test_format_sniffing(name, expected):
    assert sniff_format(name, fixture_bytes("scanners", name)) == expected


def test_unknown_format_is_named():
    with pytest.raises(ScannerError, match="could not recognise the format"):
        sniff_format("weird.json", b'{"hello": 1}')


def test_stubbed_adapters_refuse_to_run_with_an_actionable_message():
    for adapter in (TrivyAdapter(), CheckmarxAdapter()):
        assert adapter.implemented is False
        with pytest.raises(NotImplementedYet, match="under development"):
            adapter.run({}, ScanTarget())


def test_stubbed_adapters_still_parse_their_native_output():
    trivy = TrivyAdapter().parse(RawResult(payload=json.dumps({
        "Results": [{"Target": "app/requirements.txt", "Class": "lang-pkgs", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2020-28493", "PkgName": "Jinja2", "InstalledVersion": "2.11.2",
             "FixedVersion": "2.11.3", "Severity": "MEDIUM", "Title": "ReDoS in urlize",
             "CVSS": {"nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", "V3Score": 5.3}}}]}]
    }).encode()))
    assert trivy[0].cve_id == "CVE-2020-28493"
    assert trivy[0].components == ["Jinja2@2.11.2"]
    assert trivy[0].cvss_base_score == 5.3

    checkmarx = CheckmarxAdapter().parse(RawResult(payload=json.dumps({
        "results": [{"type": "sast", "severity": "HIGH", "description": "SQL injection",
                     "data": {"queryName": "SQL_Injection", "nodes": [{"fileName": "src/db.py", "line": 22}]},
                     "vulnerabilityDetails": {"cweId": 89}}]
    }).encode()))
    assert checkmarx[0].file_path == "src/db.py"
    assert checkmarx[0].line == 22
    assert checkmarx[0].scan_type == "static"


def test_every_adapter_declares_its_contract():
    from vulncano.adapters import ADAPTERS

    for tool, adapter in ADAPTERS.items():
        assert adapter.tool == tool
        assert adapter.label
        assert adapter.config_schema is not None
        assert adapter.install_hint


def test_directory_scan_finds_manifests(tmp_path):
    (tmp_path / "requirements.txt").write_text(fixture_text("manifests", "requirements.txt"))
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "package.json").write_text(fixture_text("manifests", "package.json"))
    result = ScanTarget(path=str(tmp_path)).manifests()
    names = {item.name for item in result.dependencies}
    assert "Flask" in names
    assert "lodash" in names
