"""Ties the CVSS maths to the stored findings: base score cache, NVD lookups, adapted score."""

from datetime import datetime

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .cvss import CvssError, score_all, severity_of
from .models import CVSS_METRICS, CvssFindingOverride, CvssProjectConfig, Finding


class NvdError(RuntimeError):
    pass


def project_config(session: Session, project_id: int) -> CvssProjectConfig:
    config = session.scalar(select(CvssProjectConfig).where(CvssProjectConfig.project_id == project_id))
    if config is None:
        config = CvssProjectConfig(project_id=project_id)
        session.add(config)
        session.flush()
    return config


def merged_metrics(config: CvssProjectConfig | None, override: CvssFindingOverride | None) -> dict:
    """A null on the finding override falls back to the project selection."""
    metrics = {}
    for name in CVSS_METRICS:
        value = getattr(override, name, None) if override else None
        if not value:
            value = getattr(config, name, "X") if config else "X"
        if value and value != "X":
            metrics[name] = value
    return metrics


def recompute_finding(session: Session, finding: Finding) -> Finding:
    """Refresh the cached scores. Severity follows the adapted score whenever a vector exists."""
    if not finding.cvss_vector:
        finding.adapted_score = None
        finding.adapted_vector = ""
        return finding
    config = project_config(session, finding.project_id)
    extra = merged_metrics(config, finding.cvss_override)
    try:
        scores = score_all(finding.cvss_vector, extra)
    except CvssError:
        finding.adapted_score = None
        finding.adapted_vector = ""
        return finding
    finding.cvss_base_score = scores["base_score"]
    finding.adapted_score = scores["adapted_score"]
    finding.adapted_vector = scores["vector"]
    finding.severity = scores["adapted_severity"]
    return finding


def recompute_project(session: Session, project_id: int) -> int:
    findings = session.scalars(select(Finding).where(Finding.project_id == project_id)).all()
    for finding in findings:
        recompute_finding(session, finding)
    return len(findings)


def fetch_nvd(cve_id: str) -> dict:
    """Return vector, score and publication date for a CVE, or raise with an actionable message."""
    settings = get_settings()
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    try:
        response = httpx.get(
            settings.nvd_base_url, params={"cveId": cve_id}, headers=headers, timeout=30
        )
    except httpx.HTTPError as exc:
        raise NvdError(f"NVD is unreachable: {exc}") from exc

    if response.status_code == 403:
        raise NvdError(
            "NVD refused the request. Without NVD_API_KEY the public limit is 5 requests per 30 "
            "seconds, request a key at https://nvd.nist.gov/developers/request-an-api-key"
        )
    if response.status_code == 404:
        raise NvdError(f"{cve_id} is not in the NVD")
    if response.status_code >= 400:
        raise NvdError(f"NVD answered {response.status_code}: {response.text[:200]}")

    items = response.json().get("vulnerabilities") or []
    if not items:
        raise NvdError(f"{cve_id} returned no data from the NVD")
    cve = items[0]["cve"]
    metrics = cve.get("metrics") or {}
    entry = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [None])[0]
    if not entry:
        raise NvdError(f"{cve_id} has no CVSS v3 vector in the NVD")
    data = entry["cvssData"]
    published = None
    if cve.get("published"):
        try:
            published = datetime.fromisoformat(cve["published"].replace("Z", "+00:00")).date()
        except ValueError:
            published = None
    return {
        "vector": data["vectorString"],
        "score": data["baseScore"],
        "severity": severity_of(data["baseScore"]),
        "published": published,
    }


def enrich_from_nvd(session: Session, finding: Finding, force: bool = False) -> str:
    """Fill the base vector from the NVD when the scanner did not provide one."""
    if not finding.cve_id:
        return "no CVE id"
    if finding.cvss_vector and not force:
        return "already scored"
    data = fetch_nvd(finding.cve_id)
    finding.cvss_vector = data["vector"]
    finding.cvss_base_score = data["score"]
    finding.cvss_source = "nvd"
    finding.cvss_fetched_at = datetime.utcnow()
    if data["published"] and not finding.cve_pub_date:
        finding.cve_pub_date = data["published"]
    recompute_finding(session, finding)
    return "updated"
