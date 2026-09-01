"""Checkmarx One adapter. Long running by nature, so the run step is written to submit and
return a remote scan id that the job poller picks up. The remote calls are the open contribution."""

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

ENGINES = ("sast", "sca", "kics")


class CheckmarxConfig(BaseModel):
    base_url: str = Field(default="https://eu.ast.checkmarx.net", description="Checkmarx One region base url")
    tenant: str = Field(default="", description="Tenant name")
    client_id: str = Field(default="", description="OAuth client id")
    client_secret: str = Field(default="", description="OAuth client secret",
                               json_schema_extra={"secret": True})
    project_id: str = Field(default="", description="Existing Checkmarx project id, empty to create one")
    engines: str = Field(default="sast,sca", description="Comma separated engines to run: sast, sca, kics")


class CheckmarxAdapter(ScannerAdapter):
    tool = "checkmarx"
    label = "Checkmarx One"
    config_schema = CheckmarxConfig
    accepts = ("path", "git", "archive")
    needs_credentials = True
    implemented = False
    resumable = True
    install_hint = (
        "Checkmarx One is a commercial service. Create an OAuth client under Settings, Identity and "
        "Access Management, then paste the client id and secret here."
    )

    def validate(self, config) -> tuple[bool, str | None]:
        raise NotImplementedYet(
            "The Checkmarx One adapter is under development. The credential form is in place, the "
            "authentication call is not. Contributions welcome."
        )

    def run(self, config, target: ScanTarget) -> RawResult:
        raise NotImplementedYet(
            "The Checkmarx One adapter is under development. Until it lands, export the results from "
            "the Checkmarx UI as SARIF and import them."
        )

    def poll(self, config, remote_id: str) -> RawResult:
        """Resume point for the job runner: ask Checkmarx whether remote_id has finished."""
        raise NotImplementedYet("The Checkmarx One adapter is under development.")

    def parse(self, raw: RawResult) -> list[NormalizedFinding]:
        """Reads the combined SAST and SCA results payload of the Checkmarx One results API."""
        try:
            data = json.loads(raw.payload.decode())
        except json.JSONDecodeError as exc:
            raise ScannerError(f"Checkmarx output is not JSON: {exc}") from exc

        findings = []
        for result in data.get("results") or []:
            kind = result.get("type", "sast")
            if kind == "sca":
                package = result.get("data", {}).get("packageIdentifier", "")
                findings.append(
                    NormalizedFinding(
                        title=result.get("description") or result.get("id", ""),
                        cve_id=result.get("vulnerabilityDetails", {}).get("cveName"),
                        external_id=result.get("id", ""),
                        description=(result.get("description") or "")[:8000],
                        severity=normalize_severity(result.get("severity")),
                        components=[package] if package else [],
                        scan_type="dependency",
                        tool="checkmarx",
                        cvss_vector=result.get("vulnerabilityDetails", {}).get("cvssVector", ""),
                        cvss_base_score=result.get("vulnerabilityDetails", {}).get("cvssScore"),
                    )
                )
                continue
            nodes = (result.get("data") or {}).get("nodes") or [{}]
            findings.append(
                NormalizedFinding(
                    title=(result.get("data") or {}).get("queryName") or result.get("id", ""),
                    external_id=str((result.get("vulnerabilityDetails") or {}).get("cweId", "")),
                    description=(result.get("description") or "")[:8000],
                    severity=normalize_severity(result.get("severity")),
                    components=[nodes[0].get("fileName", "")] if nodes[0].get("fileName") else [],
                    scan_type="static",
                    tool="checkmarx",
                    file_path=nodes[0].get("fileName", ""),
                    line=nodes[0].get("line"),
                )
            )
        return findings
