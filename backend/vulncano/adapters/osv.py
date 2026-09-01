"""OSV.dev adapter. No credentials, so this is the one that works the second Vulncano is installed."""

import json
from datetime import datetime

import httpx
from pydantic import BaseModel, Field

from .base import (
    NormalizedFinding,
    RawResult,
    ScannerAdapter,
    ScannerError,
    ScanTarget,
    normalize_severity,
)

BATCH_ENDPOINT = "/v1/querybatch"
VULN_ENDPOINT = "/v1/vulns/"
BATCH_SIZE = 500


class OsvConfig(BaseModel):
    base_url: str = Field(default="https://api.osv.dev", description="OSV API base url")
    timeout: int = Field(default=30, description="HTTP timeout in seconds")


def _severity_from_entry(entry: dict) -> tuple[str, str]:
    """OSV gives either a CVSS vector, a database_specific severity, or nothing useful."""
    vector = ""
    for item in entry.get("severity") or []:
        if item.get("type", "").startswith("CVSS_V3") and item.get("score"):
            vector = item["score"]
            break
    label = (entry.get("database_specific") or {}).get("severity")
    return normalize_severity(label), vector


def _affected_coordinates(entry: dict, queried: str) -> list[str]:
    names = set()
    for affected in entry.get("affected") or []:
        package = affected.get("package") or {}
        if package.get("name"):
            names.add(package["name"])
    if not names:
        return [queried]
    version = queried.rsplit("@", 1)[-1] if "@" in queried else ""
    return sorted(f"{name}@{version}" if version else name for name in names)


def _fixed_version(entry: dict) -> str:
    for affected in entry.get("affected") or []:
        for entry_range in affected.get("ranges") or []:
            for event in entry_range.get("events") or []:
                if event.get("fixed"):
                    return event["fixed"]
        versions = affected.get("database_specific", {}).get("last_known_affected_version_range")
        if versions:
            return ""
    return ""


def _published_date(entry: dict):
    raw = entry.get("published") or entry.get("modified")
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).date()
    except ValueError:
        return None


class OsvAdapter(ScannerAdapter):
    tool = "osv"
    label = "OSV.dev"
    config_schema = OsvConfig
    accepts = ("requirements.txt", "pyproject.toml", "poetry.lock", "pom.xml", "package.json",
               "package-lock.json", "yarn.lock", "go.mod", "go.sum", "Cargo.lock", "Gemfile.lock",
               "composer.lock", "*.csproj", "path")
    needs_credentials = False
    install_hint = "Nothing to install, OSV.dev is a public API."

    def validate(self, config) -> tuple[bool, str | None]:
        settings = OsvConfig(**(config or {}))
        try:
            response = httpx.post(
                settings.base_url.rstrip("/") + BATCH_ENDPOINT,
                json={"queries": [{"package": {"name": "jinja2", "ecosystem": "PyPI"}, "version": "2.4.1"}]},
                timeout=settings.timeout,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return False, f"cannot reach {settings.base_url}: {exc}"
        return True, "OSV.dev reachable"

    def run(self, config, target: ScanTarget) -> RawResult:
        settings = OsvConfig(**(config or {}))
        manifests = target.manifests()
        dependencies = manifests.deduplicated()
        if not dependencies:
            raise ScannerError(
                "no dependencies were parsed from the target. "
                + ("Warnings: " + "; ".join(manifests.warnings) if manifests.warnings else "")
            )

        queries = [
            {"package": {"name": item.name, "ecosystem": item.ecosystem}, "version": item.version}
            for item in dependencies
        ]
        log = [f"parsed {len(dependencies)} dependencies from {target.describe()}"]
        log.extend(manifests.warnings)

        matches = []
        with httpx.Client(base_url=settings.base_url.rstrip("/"), timeout=settings.timeout) as client:
            for start in range(0, len(queries), BATCH_SIZE):
                chunk = queries[start:start + BATCH_SIZE]
                try:
                    response = client.post(BATCH_ENDPOINT, json={"queries": chunk})
                    response.raise_for_status()
                except httpx.HTTPStatusError as exc:
                    raise ScannerError(
                        f"OSV.dev answered {exc.response.status_code} for a batch of {len(chunk)} packages: "
                        f"{exc.response.text[:300]}"
                    ) from exc
                except httpx.HTTPError as exc:
                    raise ScannerError(f"OSV.dev is unreachable: {exc}") from exc
                for query, result in zip(chunk, response.json().get("results", [])):
                    for vulnerability in result.get("vulns") or []:
                        matches.append((query, vulnerability["id"]))
                log.append(f"queried {len(chunk)} packages, {len(matches)} advisories so far")

            entries = []
            # OSV answers with the GHSA and the CVE as separate ids for one advisory, so every
            # identifier an entry claims points back at the same record
            by_identifier = {}
            for query, vuln_id in matches:
                coordinate = f"{query['package']['name']}@{query['version']}"
                known = by_identifier.get(vuln_id)
                if known is not None:
                    known["coordinates"].append(coordinate)
                    continue
                try:
                    detail = client.get(VULN_ENDPOINT + vuln_id)
                    detail.raise_for_status()
                except httpx.HTTPError as exc:
                    log.append(f"could not fetch {vuln_id}: {exc}")
                    continue
                entry = detail.json()
                record = {"coordinates": [coordinate], "entry": entry}
                entries.append(record)
                for identifier in [entry.get("id", vuln_id), vuln_id, *(entry.get("aliases") or [])]:
                    by_identifier.setdefault(identifier, record)

        log.append(f"resolved {len(entries)} advisories")
        return RawResult(
            payload=json.dumps({"results": entries}, indent=2).encode(),
            log="\n".join(log),
        )

    def parse(self, raw: RawResult) -> list[NormalizedFinding]:
        try:
            data = json.loads(raw.payload.decode())
        except json.JSONDecodeError as exc:
            raise ScannerError(f"OSV output is not JSON: {exc}") from exc

        findings = []
        for record in data.get("results", []):
            entry = record["entry"]
            severity, vector = _severity_from_entry(entry)
            aliases = entry.get("aliases") or []
            cve = next((alias for alias in aliases if alias.startswith("CVE-")), None)
            if entry["id"].startswith("CVE-"):
                cve = entry["id"]
            components = sorted(set(record.get("coordinates") or []))
            findings.append(
                NormalizedFinding(
                    title=entry.get("summary") or entry["id"],
                    cve_id=cve,
                    external_id=entry["id"],
                    description=entry.get("details", "")[:8000],
                    severity=severity,
                    components=components or _affected_coordinates(entry, entry["id"]),
                    scan_type="dependency",
                    tool=self.tool,
                    cve_pub_date=_published_date(entry),
                    cvss_vector=vector,
                    fixed_version=_fixed_version(entry),
                    references=[ref["url"] for ref in entry.get("references") or [] if ref.get("url")][:10],
                )
            )
        return findings
