"""Import adapters for files the user already has: SARIF, CycloneDX, Grype, Dependency-Check
and the flat spreadsheet a security team sends by mail."""

import csv
import io
import json
from datetime import datetime

from pydantic import BaseModel

from .base import NormalizedFinding, RawResult, ScannerAdapter, ScannerError, ScanTarget, normalize_severity

SARIF_LEVELS = {"error": "High", "warning": "Medium", "note": "Low", "none": "Info"}
DC_VECTOR_PARTS = (
    ("attackVector", "AV", {"NETWORK": "N", "ADJACENT_NETWORK": "A", "LOCAL": "L", "PHYSICAL": "P"}),
    ("attackComplexity", "AC", {"LOW": "L", "HIGH": "H"}),
    ("privilegesRequired", "PR", {"NONE": "N", "LOW": "L", "HIGH": "H"}),
    ("userInteraction", "UI", {"NONE": "N", "REQUIRED": "R"}),
    ("scope", "S", {"UNCHANGED": "U", "CHANGED": "C"}),
    ("confidentialityImpact", "C", {"HIGH": "H", "LOW": "L", "NONE": "N"}),
    ("integrityImpact", "I", {"HIGH": "H", "LOW": "L", "NONE": "N"}),
    ("availabilityImpact", "A", {"HIGH": "H", "LOW": "L", "NONE": "N"}),
)
SPREADSHEET_ALIASES = {
    "cve": "cve", "cve_id": "cve", "vulnerability": "cve", "id": "cve",
    "package": "package", "component": "package", "library": "package",
    "purl": "purl",
    "cwe": "cwe",
    "description": "description", "summary": "description", "title": "description",
    "base_score": "base_score", "score": "base_score", "cvss": "base_score", "cvss_score": "base_score",
    "cvss_vector": "vector", "vector": "vector",
    "remediation": "remediation", "fix": "remediation", "fixed_version": "remediation",
    "severity": "severity",
    "version": "version",
}


class NoConfig(BaseModel):
    """Importers take a file, not credentials."""


def _decode(raw: RawResult) -> str:
    return raw.payload.decode("utf-8-sig", errors="replace")


def _load_json(raw: RawResult, label: str) -> dict:
    try:
        return json.loads(_decode(raw))
    except json.JSONDecodeError as exc:
        raise ScannerError(f"{label} file is not valid JSON: {exc}") from exc


def _parse_date(value):
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    for form in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, form).date()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text).date()
    except ValueError:
        return None


def _cvss_from_ratings(ratings: list) -> tuple[str, float | None, str | None]:
    vector, score, severity = "", None, None
    for rating in ratings or []:
        candidate = rating.get("vector", "")
        preferred = "cvssv3" in str(rating.get("method", "")).lower()
        if candidate and (preferred or not vector):
            vector = candidate
        if rating.get("score") is not None and score is None:
            score = float(rating["score"])
        if rating.get("severity") and severity is None:
            severity = rating["severity"]
    return vector, score, severity


class ImportAdapter(ScannerAdapter):
    """Shared behaviour for the file importers: no run step, the file is the scan."""

    config_schema = NoConfig
    needs_credentials = False
    accepts = ("file",)
    install_hint = "Nothing to install, upload the file the tool produced."

    def validate(self, config) -> tuple[bool, str | None]:
        return True, "importers need no credentials"

    def run(self, config, target: ScanTarget) -> RawResult:
        if not target.files:
            raise ScannerError(f"{self.label} import needs a file, none was uploaded")
        uploaded = target.files[0]
        return RawResult(payload=uploaded.content, log=f"imported {uploaded.name} ({len(uploaded.content)} bytes)")


class SarifAdapter(ImportAdapter):
    tool = "sarif"
    label = "SARIF"

    def parse(self, raw: RawResult) -> list[NormalizedFinding]:
        data = _load_json(raw, "SARIF")
        if "runs" not in data:
            raise ScannerError("SARIF file has no runs array, is this really a SARIF report?")
        findings = []
        for run in data.get("runs", []):
            driver = (run.get("tool") or {}).get("driver") or {}
            tool_name = driver.get("name", "sarif")
            rules = {}
            for rule in driver.get("rules") or []:
                rules[rule.get("id")] = rule
            for result in run.get("results") or []:
                rule_id = result.get("ruleId") or result.get("rule", {}).get("id", "")
                rule = rules.get(rule_id, {})
                level = result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning"
                message = (result.get("message") or {}).get("text") or rule.get("shortDescription", {}).get("text", "")
                location = ((result.get("locations") or [{}])[0].get("physicalLocation") or {})
                artifact = (location.get("artifactLocation") or {}).get("uri", "")
                region = location.get("region") or {}
                description = (rule.get("fullDescription") or {}).get("text") or message
                severity = SARIF_LEVELS.get(str(level).lower(), normalize_severity(level))
                tags = (rule.get("properties") or {}).get("tags") or []
                cwe = next((tag for tag in tags if str(tag).upper().startswith("CWE")), "")
                findings.append(
                    NormalizedFinding(
                        title=message[:480] or rule_id,
                        external_id=cwe or rule_id,
                        description=description[:8000],
                        severity=severity,
                        components=[artifact] if artifact else [],
                        scan_type="static",
                        tool=tool_name,
                        file_path=artifact,
                        line=region.get("startLine"),
                    )
                )
        return findings


class CycloneDxAdapter(ImportAdapter):
    tool = "cyclonedx"
    label = "CycloneDX"

    def parse(self, raw: RawResult) -> list[NormalizedFinding]:
        data = _load_json(raw, "CycloneDX")
        if "bomFormat" not in data and "components" not in data and "vulnerabilities" not in data:
            raise ScannerError("this does not look like a CycloneDX document (no bomFormat, components or vulnerabilities)")

        by_ref = {}
        for component in data.get("components") or []:
            coordinate = component.get("name", "")
            if component.get("version"):
                coordinate = f"{coordinate}@{component['version']}"
            for key in filter(None, (component.get("bom-ref"), component.get("purl"))):
                by_ref[key] = coordinate

        findings = []
        for vulnerability in data.get("vulnerabilities") or []:
            vector, score, severity = _cvss_from_ratings(vulnerability.get("ratings"))
            components = []
            for affects in vulnerability.get("affects") or []:
                ref = affects.get("ref", "")
                components.append(by_ref.get(ref, by_ref.get(ref.split("?")[0], ref)))
            identifier = vulnerability.get("id", "")
            advisories = [item.get("url", "") for item in vulnerability.get("advisories") or []]
            recommendation = vulnerability.get("recommendation", "")
            findings.append(
                NormalizedFinding(
                    title=(vulnerability.get("description") or identifier)[:480],
                    cve_id=identifier if identifier.upper().startswith("CVE-") else None,
                    external_id=identifier,
                    description=(vulnerability.get("detail") or vulnerability.get("description") or "")[:8000],
                    severity=normalize_severity(severity),
                    components=sorted(set(filter(None, components))),
                    scan_type="dependency",
                    tool=(vulnerability.get("source") or {}).get("name", "cyclonedx"),
                    cve_pub_date=_parse_date(vulnerability.get("published")),
                    cvss_vector=vector,
                    cvss_base_score=score,
                    mitigation=recommendation,
                    references=[url for url in advisories if url][:10],
                )
            )
        if not findings:
            raise ScannerError("the CycloneDX document has no vulnerabilities section, nothing to import")
        return findings


class GrypeAdapter(ImportAdapter):
    tool = "grype"
    label = "Grype"

    def parse(self, raw: RawResult) -> list[NormalizedFinding]:
        data = _load_json(raw, "Grype")
        if "matches" not in data:
            raise ScannerError("Grype output has no matches array, run grype with -o json")
        findings = []
        for match in data.get("matches") or []:
            vulnerability = match.get("vulnerability") or {}
            artifact = match.get("artifact") or {}
            related = match.get("relatedVulnerabilities") or []
            identifier = vulnerability.get("id", "")
            cve = identifier if identifier.upper().startswith("CVE-") else next(
                (item.get("id") for item in related if str(item.get("id", "")).upper().startswith("CVE-")), None
            )
            cvss_entries = (vulnerability.get("cvss") or []) + [
                entry for item in related for entry in item.get("cvss") or []
            ]
            vector = next((entry.get("vector", "") for entry in cvss_entries if entry.get("vector")), "")
            score = next(
                (entry.get("metrics", {}).get("baseScore") for entry in cvss_entries
                 if entry.get("metrics", {}).get("baseScore") is not None),
                None,
            )
            description = vulnerability.get("description") or next(
                (item.get("description", "") for item in related if item.get("description")), ""
            )
            fixed = ", ".join((vulnerability.get("fix") or {}).get("versions") or [])
            coordinate = f"{artifact.get('name', '')}@{artifact.get('version', '')}".strip("@")
            findings.append(
                NormalizedFinding(
                    title=(description or identifier)[:480],
                    cve_id=cve,
                    external_id=identifier,
                    description=description[:8000],
                    severity=normalize_severity(vulnerability.get("severity")),
                    components=[coordinate] if coordinate else [],
                    scan_type="container" if artifact.get("type") in {"apk", "deb", "rpm"} else "dependency",
                    tool="grype",
                    cvss_vector=vector,
                    cvss_base_score=float(score) if score is not None else None,
                    fixed_version=fixed,
                    file_path=(artifact.get("locations") or [{}])[0].get("path", ""),
                )
            )
        return findings


class DependencyCheckAdapter(ImportAdapter):
    tool = "dependency-check"
    label = "OWASP Dependency-Check"

    def parse(self, raw: RawResult) -> list[NormalizedFinding]:
        data = _load_json(raw, "Dependency-Check")
        if "dependencies" not in data:
            raise ScannerError("Dependency-Check report has no dependencies array, use the JSON report format")
        findings = []
        for dependency in data.get("dependencies") or []:
            packages = dependency.get("packages") or []
            coordinate = dependency.get("fileName", "")
            for package in packages:
                purl = package.get("id", "")
                if purl.startswith("pkg:"):
                    coordinate = purl.split("/")[-1]
                    break
            for vulnerability in dependency.get("vulnerabilities") or []:
                cvss3 = vulnerability.get("cvssv3") or {}
                parts = []
                for source_key, metric, mapping in DC_VECTOR_PARTS:
                    value = mapping.get(str(cvss3.get(source_key, "")).upper())
                    if value:
                        parts.append(f"{metric}:{value}")
                vector = "CVSS:3.1/" + "/".join(parts) if len(parts) == len(DC_VECTOR_PARTS) else ""
                cwes = ", ".join(vulnerability.get("cwes") or [])
                identifier = vulnerability.get("name", "")
                findings.append(
                    NormalizedFinding(
                        title=(vulnerability.get("description") or identifier)[:480],
                        cve_id=identifier if identifier.upper().startswith("CVE-") else None,
                        external_id=cwes or identifier,
                        description=(vulnerability.get("description") or "")[:8000],
                        severity=normalize_severity(
                            cvss3.get("baseSeverity") or vulnerability.get("severity")
                        ),
                        components=[coordinate] if coordinate else [],
                        scan_type="dependency",
                        tool="dependency-check",
                        cvss_vector=vector,
                        cvss_base_score=cvss3.get("baseScore"),
                        file_path=dependency.get("filePath", ""),
                    )
                )
        return findings


class SpreadsheetAdapter(ImportAdapter):
    tool = "spreadsheet"
    label = "Spreadsheet (CSV)"

    def parse(self, raw: RawResult) -> list[NormalizedFinding]:
        text = _decode(raw)
        try:
            dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(io.StringIO(text), dialect=dialect)
        if not reader.fieldnames:
            raise ScannerError("the spreadsheet has no header row")

        mapping = {}
        for column in reader.fieldnames:
            key = SPREADSHEET_ALIASES.get(column.strip().lower().replace(" ", "_"))
            if key:
                mapping[column] = key
        if "cve" not in mapping.values() and "package" not in mapping.values():
            raise ScannerError(
                "the spreadsheet needs at least a CVE or a PACKAGE column. "
                f"Recognised columns: {', '.join(sorted(set(SPREADSHEET_ALIASES)))}"
            )

        findings = []
        for number, row in enumerate(reader, start=2):
            values = {}
            for column, key in mapping.items():
                values[key] = (row.get(column) or "").strip()
            if not any(values.values()):
                continue
            component = values.get("package", "")
            if values.get("version") and component and "@" not in component:
                component = f"{component}@{values['version']}"
            elif not component and values.get("purl"):
                component = values["purl"].split("/")[-1]
            score = values.get("base_score") or ""
            try:
                base_score = float(score) if score else None
            except ValueError:
                base_score = None
                values["description"] = f"{values.get('description', '')} (row {number}: unreadable score {score})"
            cve = values.get("cve", "")
            findings.append(
                NormalizedFinding(
                    title=(values.get("description") or cve or component)[:480],
                    cve_id=cve if cve.upper().startswith("CVE-") else None,
                    external_id=values.get("cwe") or cve,
                    description=values.get("description", "")[:8000],
                    severity=normalize_severity(values.get("severity"), default="Medium"),
                    components=[component] if component else [],
                    scan_type="dependency",
                    tool="spreadsheet",
                    cvss_vector=values.get("vector", ""),
                    cvss_base_score=base_score,
                    fixed_version=values.get("remediation", ""),
                )
            )
        if not findings:
            raise ScannerError("no data rows found in the spreadsheet")
        return findings


def sniff_format(name: str, content: bytes) -> str:
    """Pick an importer for an uploaded file so the user does not have to name the format."""
    lowered = name.lower()
    if lowered.endswith((".csv", ".tsv")):
        return SpreadsheetAdapter.tool
    if lowered.endswith(".sarif"):
        return SarifAdapter.tool
    try:
        data = json.loads(content.decode("utf-8-sig", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return SpreadsheetAdapter.tool
    if not isinstance(data, dict):
        raise ScannerError(f"{name}: unsupported file, the JSON root is not an object")
    if "runs" in data:
        return SarifAdapter.tool
    if "bomFormat" in data or "components" in data:
        return CycloneDxAdapter.tool
    if "matches" in data:
        return GrypeAdapter.tool
    if "dependencies" in data and "projectInfo" in data:
        return DependencyCheckAdapter.tool
    if "vulnerabilities" in data:
        return CycloneDxAdapter.tool
    raise ScannerError(
        f"{name}: could not recognise the format. Supported imports: SARIF, CycloneDX, "
        "Grype JSON, OWASP Dependency-Check JSON and a CSV spreadsheet."
    )
