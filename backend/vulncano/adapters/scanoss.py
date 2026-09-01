"""SCANOSS adapter. Sends the parsed dependency list to the SCANOSS dependency service and
reads back the CycloneDX shaped answer (dependencies plus vulnerabilities)."""

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

DEPENDENCY_ENDPOINT = "/api/dependencies"
ECOSYSTEM_PURL = {
    "PyPI": "pkg:pypi/",
    "npm": "pkg:npm/",
    "Maven": "pkg:maven/",
    "Go": "pkg:golang/",
    "crates.io": "pkg:cargo/",
    "RubyGems": "pkg:gem/",
    "Packagist": "pkg:composer/",
    "NuGet": "pkg:nuget/",
}


class ScanossConfig(BaseModel):
    api_url: str = Field(default="https://api.osskb.org", description="SCANOSS API base url")
    api_key: str = Field(default="", description="SCANOSS API key, the dependency endpoint requires one",
                         json_schema_extra={"secret": True})
    sbom_ignore: str = Field(default="", description="Optional SBOM ignore file contents (one purl per line)")
    timeout: int = Field(default=60, description="HTTP timeout in seconds")


def _headers(settings: ScanossConfig) -> dict:
    headers = {"Content-Type": "application/json"}
    if settings.api_key:
        headers["X-Session"] = settings.api_key
    return headers


def _purl_for(dependency) -> str:
    prefix = ECOSYSTEM_PURL.get(dependency.ecosystem)
    if not prefix:
        return ""
    name = dependency.name.replace(":", "/") if dependency.ecosystem == "Maven" else dependency.name
    return f"{prefix}{name}"


def _ignored_purls(raw: str) -> set[str]:
    return {line.strip() for line in (raw or "").splitlines() if line.strip() and not line.startswith("#")}


def _published_date(value: str | None):
    if not value:
        return None
    for form in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, form).date()
        except ValueError:
            continue
    return None


def _resolve_reference(ref: str, components: dict) -> str:
    """affects[].ref points at a bom-ref or a purl, both have to come back as component@version."""
    if ref in components:
        return components[ref]
    bare = ref.split("?")[0]
    if bare in components:
        return components[bare]
    if "@" in bare:
        name, version = bare.rsplit("@", 1)
        return f"{name.rsplit('/', 1)[-1]}@{version}"
    return bare


class ScanossAdapter(ScannerAdapter):
    tool = "scanoss"
    label = "SCANOSS"
    config_schema = ScanossConfig
    accepts = ("requirements.txt", "pom.xml", "package.json", "package-lock.json", "go.mod",
               "Gemfile.lock", "composer.lock", "*.csproj", "path")
    needs_credentials = True
    install_hint = (
        "The dependency endpoint needs an API key even on the free https://api.osskb.org host. "
        "Request one at https://www.scanoss.com/ and paste it here."
    )

    def validate(self, config) -> tuple[bool, str | None]:
        settings = ScanossConfig(**(config or {}))
        payload = {"depth": 1, "files": [{"file": "requirements.txt", "purls": [{"purl": "pkg:pypi/jinja2"}]}]}
        try:
            response = httpx.post(
                settings.api_url.rstrip("/") + DEPENDENCY_ENDPOINT,
                json=payload,
                headers=_headers(settings),
                timeout=settings.timeout,
            )
        except httpx.HTTPError as exc:
            return False, f"cannot reach {settings.api_url}: {exc}"
        if response.status_code in (401, 403):
            return False, (
                "SCANOSS refused the request, the dependency endpoint needs an API key"
                if not settings.api_key
                else f"SCANOSS rejected the API key (HTTP {response.status_code})"
            )
        if response.status_code >= 400:
            return False, f"SCANOSS answered {response.status_code}: {response.text[:200]}"
        return True, "SCANOSS reachable"

    def run(self, config, target: ScanTarget) -> RawResult:
        settings = ScanossConfig(**(config or {}))
        manifests = target.manifests()
        dependencies = manifests.deduplicated()
        if not dependencies:
            raise ScannerError("no dependencies were parsed from the target, nothing to send to SCANOSS")

        ignored = _ignored_purls(settings.sbom_ignore)
        purls = []
        log = [f"parsed {len(dependencies)} dependencies from {target.describe()}"]
        log.extend(manifests.warnings)
        for dependency in dependencies:
            purl = _purl_for(dependency)
            if not purl:
                log.append(f"{dependency.name}: ecosystem {dependency.ecosystem} has no SCANOSS purl type")
                continue
            if purl in ignored or f"{purl}@{dependency.version}" in ignored:
                log.append(f"{purl} ignored by the SBOM ignore file")
                continue
            purls.append({"purl": f"{purl}@{dependency.version}" if dependency.version else purl})

        payload = {"depth": 1, "files": [{"file": target.describe(), "purls": purls}]}
        try:
            response = httpx.post(
                settings.api_url.rstrip("/") + DEPENDENCY_ENDPOINT,
                json=payload,
                headers=_headers(settings),
                timeout=settings.timeout,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (401, 403):
                raise ScannerError(
                    "SCANOSS refused the request: the dependency endpoint needs an API key. "
                    + ("The key in the scanner settings was rejected." if settings.api_key
                       else "No key is configured, request a free one at https://www.scanoss.com/.")
                ) from exc
            raise ScannerError(
                f"SCANOSS answered {exc.response.status_code}: {exc.response.text[:300]}"
            ) from exc
        except httpx.HTTPError as exc:
            raise ScannerError(f"SCANOSS is unreachable: {exc}") from exc

        log.append(f"sent {len(purls)} purls")
        return RawResult(payload=response.content, log="\n".join(log))

    def parse(self, raw: RawResult) -> list[NormalizedFinding]:
        try:
            data = json.loads(raw.payload.decode())
        except json.JSONDecodeError as exc:
            raise ScannerError(f"SCANOSS output is not JSON: {exc}") from exc

        components = {}
        for group in data.get("files", []) or []:
            for dependency in group.get("dependencies", []) or []:
                purl = dependency.get("purl", "")
                version = dependency.get("version", "")
                name = purl.split("/")[-1] if purl else dependency.get("component", "")
                coordinate = f"{name}@{version}" if version else name
                components[purl] = coordinate
                if version:
                    components[f"{purl}@{version}"] = coordinate

        findings = []
        for group in data.get("files", []) or []:
            for dependency in group.get("dependencies", []) or []:
                purl = dependency.get("purl", "")
                coordinate = components.get(purl, purl)
                for vulnerability in dependency.get("vulnerabilities", []) or []:
                    findings.append(self._finding(vulnerability, [coordinate]))

        for vulnerability in data.get("vulnerabilities", []) or []:
            affected = [
                _resolve_reference(entry.get("ref", ""), components)
                for entry in vulnerability.get("affects", []) or []
            ]
            findings.append(self._finding(vulnerability, sorted(set(filter(None, affected)))))

        return findings

    def _finding(self, vulnerability: dict, components: list[str]) -> NormalizedFinding:
        identifier = vulnerability.get("CVE") or vulnerability.get("cve") or vulnerability.get("id", "")
        cve = identifier if str(identifier).upper().startswith("CVE-") else None
        ratings = vulnerability.get("ratings") or []
        vector = next((rating.get("vector", "") for rating in ratings if rating.get("vector")), "")
        score = next((rating.get("score") for rating in ratings if rating.get("score") is not None), None)
        severity_label = vulnerability.get("severity") or next(
            (rating.get("severity") for rating in ratings if rating.get("severity")), None
        )
        return NormalizedFinding(
            title=vulnerability.get("summary") or vulnerability.get("description") or identifier,
            cve_id=cve,
            external_id=str(identifier),
            description=vulnerability.get("description", "")[:8000],
            severity=normalize_severity(severity_label),
            components=components,
            scan_type="dependency",
            tool=self.tool,
            cve_pub_date=_published_date(vulnerability.get("published")),
            cvss_vector=vector,
            cvss_base_score=float(score) if score is not None else None,
            fixed_version=vulnerability.get("fixed") or vulnerability.get("recommendation", ""),
        )
