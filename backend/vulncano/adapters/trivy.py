"""Trivy adapter. The contract, the settings form and the parser signature are here; the
run step is the open contribution. See CONTRIBUTING.md."""

import json

from pydantic import BaseModel, Field

from .base import (
    NormalizedFinding,
    NotImplementedYet,
    RawResult,
    ScannerAdapter,
    ScannerError,
    ScanTarget,
    normalize_severity,
)


class TrivyConfig(BaseModel):
    binary_path: str = Field(default="trivy", description="Path to the trivy binary, or just trivy if it is on PATH")
    offline: bool = Field(default=False, description="Run with --offline-scan, no vulnerability db refresh")
    cache_dir: str = Field(default="", description="Override the trivy cache directory")
    severity_floor: str = Field(default="LOW", description="Lowest severity to report (UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL)")
    db_repository: str = Field(default="", description="Custom vulnerability database repository")


class TrivyAdapter(ScannerAdapter):
    tool = "trivy"
    label = "Trivy"
    config_schema = TrivyConfig
    accepts = ("requirements.txt", "pom.xml", "package-lock.json", "image", "path", "sbom")
    needs_credentials = False
    implemented = False
    install_hint = (
        "Install Trivy from https://trivy.dev/latest/getting-started/installation/ and make sure "
        "the binary is on PATH or set its full path in the scanner settings."
    )

    def validate(self, config) -> tuple[bool, str | None]:
        raise NotImplementedYet(
            "The Trivy adapter is under development. The configuration form and the parser are in "
            "place, launching the binary is not. Contributions welcome."
        )

    def run(self, config, target: ScanTarget) -> RawResult:
        raise NotImplementedYet(
            "The Trivy adapter is under development. Until it lands, run trivy yourself and import "
            "the result: trivy fs --format cyclonedx -o result.json . then upload result.json as a "
            "CycloneDX import."
        )

    def parse(self, raw: RawResult) -> list[NormalizedFinding]:
        """Reads trivy --format json: Results[].Vulnerabilities[] and Results[].Misconfigurations[]."""
        try:
            data = json.loads(raw.payload.decode())
        except json.JSONDecodeError as exc:
            raise ScannerError(f"Trivy output is not JSON: {exc}") from exc

        findings = []
        for result in data.get("Results") or []:
            target_name = result.get("Target", "")
            for vulnerability in result.get("Vulnerabilities") or []:
                cvss = vulnerability.get("CVSS") or {}
                vector, score = "", None
                for source in ("nvd", "redhat", "ghsa"):
                    entry = cvss.get(source) or {}
                    if entry.get("V3Vector"):
                        vector, score = entry["V3Vector"], entry.get("V3Score")
                        break
                coordinate = f"{vulnerability.get('PkgName', '')}@{vulnerability.get('InstalledVersion', '')}"
                findings.append(
                    NormalizedFinding(
                        title=vulnerability.get("Title") or vulnerability.get("VulnerabilityID", ""),
                        cve_id=vulnerability.get("VulnerabilityID")
                        if str(vulnerability.get("VulnerabilityID", "")).upper().startswith("CVE-")
                        else None,
                        external_id=vulnerability.get("VulnerabilityID", ""),
                        description=(vulnerability.get("Description") or "")[:8000],
                        severity=normalize_severity(vulnerability.get("Severity")),
                        components=[coordinate.strip("@")],
                        scan_type="container" if result.get("Class") == "os-pkgs" else "dependency",
                        tool="trivy",
                        cvss_vector=vector,
                        cvss_base_score=score,
                        fixed_version=vulnerability.get("FixedVersion", ""),
                        file_path=target_name,
                    )
                )
            for misconfiguration in result.get("Misconfigurations") or []:
                findings.append(
                    NormalizedFinding(
                        title=misconfiguration.get("Title", ""),
                        external_id=misconfiguration.get("ID", ""),
                        description=(misconfiguration.get("Description") or "")[:8000],
                        severity=normalize_severity(misconfiguration.get("Severity")),
                        components=[target_name] if target_name else [],
                        scan_type="static",
                        tool="trivy",
                        mitigation=misconfiguration.get("Resolution", ""),
                        file_path=target_name,
                        line=(misconfiguration.get("CauseMetadata") or {}).get("StartLine"),
                    )
                )
        return findings
