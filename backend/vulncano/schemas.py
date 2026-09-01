from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .models import DEFAULT_SLA, PLAN_STATUSES, SCAN_TYPES, SEVERITIES, STATUSES

ORM = ConfigDict(from_attributes=True)


class ProjectIn(BaseModel):
    key: str = Field(min_length=1, max_length=32)
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    sla_critical: int = DEFAULT_SLA["Critical"]
    sla_high: int = DEFAULT_SLA["High"]
    sla_medium: int = DEFAULT_SLA["Medium"]
    sla_low: int = DEFAULT_SLA["Low"]
    sla_info: int = DEFAULT_SLA["Info"]

    @field_validator("key")
    @classmethod
    def upper_key(cls, value: str) -> str:
        cleaned = value.strip().upper().replace(" ", "-")
        if not cleaned.replace("-", "").replace("_", "").isalnum():
            raise ValueError("project key must be letters, digits, dash or underscore")
        return cleaned


class ProjectOut(ProjectIn):
    model_config = ORM
    id: int
    created_at: datetime
    finding_count: int = 0
    open_count: int = 0


class PatchIn(BaseModel):
    fixed_version: str = ""
    patch_pub_date: date | None = None
    functional_impact: str = ""
    operational_impact: str = ""
    regression_tests: str = ""
    schedule: str = ""
    applied_at: date | None = None
    comments: str = ""
    plan_id: int | None = None


class PatchOut(PatchIn):
    model_config = ORM
    id: int
    ref: str
    finding_id: int


class FindingIn(BaseModel):
    project_id: int
    cve_id: str | None = None
    external_id: str = ""
    title: str = ""
    description: str = ""
    cve_pub_date: date | None = None
    severity: str = "Medium"
    components: str = ""
    scan_type: str = "dependency"
    tool: str = ""
    origin: str = "Manually"
    status: str = "New"
    mitigation: str = ""
    file_path: str = ""
    line: int | None = None
    reported: bool = False
    cvss_vector: str = ""

    @field_validator("severity")
    @classmethod
    def known_severity(cls, value: str) -> str:
        if value not in SEVERITIES:
            raise ValueError(f"severity must be one of {', '.join(SEVERITIES)}")
        return value

    @field_validator("status")
    @classmethod
    def known_status(cls, value: str) -> str:
        if value not in STATUSES:
            raise ValueError(f"status must be one of {', '.join(STATUSES)}")
        return value

    @field_validator("scan_type")
    @classmethod
    def known_scan_type(cls, value: str) -> str:
        if value not in SCAN_TYPES:
            raise ValueError(f"scan_type must be one of {', '.join(SCAN_TYPES)}")
        return value


class FindingUpdate(BaseModel):
    project_id: int | None = None
    cve_id: str | None = None
    external_id: str | None = None
    title: str | None = None
    description: str | None = None
    cve_pub_date: date | None = None
    severity: str | None = None
    components: str | None = None
    scan_type: str | None = None
    tool: str | None = None
    origin: str | None = None
    status: str | None = None
    mitigation: str | None = None
    file_path: str | None = None
    line: int | None = None
    reported: bool | None = None
    cvss_vector: str | None = None


class FindingOut(BaseModel):
    model_config = ORM
    id: int
    ref: str
    project_id: int
    project_key: str = ""
    cve_id: str | None
    external_id: str
    title: str
    description: str
    cve_pub_date: date | None
    severity: str
    components: str
    scan_type: str
    tool: str
    origin: str
    status: str
    mitigation: str
    file_path: str
    line: int | None
    reported: bool
    cvss_vector: str
    cvss_base_score: float | None
    cvss_source: str
    adapted_score: float | None
    adapted_vector: str
    regressed_at: datetime | None
    created_at: datetime
    updated_at: datetime
    patch: PatchOut | None = None
    plan_id: int | None = None
    plan_name: str = ""
    age_days: int = 0
    sla_days: int = 0
    sla_overdue: bool = False
    days_since_publication: int | None = None


class FindingPage(BaseModel):
    items: list[FindingOut]
    total: int
    counts_by_severity: dict[str, int] = {}


class BatchStatus(BaseModel):
    ids: list[int]
    status: str | None = None
    reported: bool | None = None
    severity: str | None = None


class IdList(BaseModel):
    ids: list[int]


class PlanIn(BaseModel):
    project_id: int
    name: str = Field(min_length=1, max_length=200)
    target_version: str = ""
    target_date: date | None = None
    owner: str = ""
    status: str = "Draft"
    notes: str = ""
    finding_ids: list[int] = []

    @field_validator("status")
    @classmethod
    def known_status(cls, value: str) -> str:
        if value not in PLAN_STATUSES:
            raise ValueError(f"status must be one of {', '.join(PLAN_STATUSES)}")
        return value


class PlanUpdate(BaseModel):
    name: str | None = None
    target_version: str | None = None
    target_date: date | None = None
    owner: str | None = None
    status: str | None = None
    notes: str | None = None


class PlanOut(BaseModel):
    model_config = ORM
    id: int
    ref: str
    project_id: int
    name: str
    target_version: str
    target_date: date | None
    owner: str
    status: str
    notes: str
    created_at: datetime
    finding_count: int = 0
    fixed_count: int = 0
    overdue: bool = False
    missing: list[str] = []


class ScannerConfigIn(BaseModel):
    project_id: int | None = None
    tool: str
    name: str
    enabled: bool = True
    config: dict = {}


class ScannerConfigOut(BaseModel):
    id: int
    project_id: int | None
    tool: str
    name: str
    enabled: bool
    config: dict
    credential_set: bool
    created_at: datetime


class ScanOut(BaseModel):
    model_config = ORM
    id: int
    ref: str
    project_id: int
    scanner_config_id: int | None
    tool: str
    source: str
    status: str
    log: str
    error: str
    parsed_count: int
    imported_count: int
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


class PreviewRow(BaseModel):
    suggested_ref: str = ""
    include: bool = True
    duplicate_of: str | None = None
    duplicate_reason: str = ""
    regression_of: str | None = None
    project_id: int
    cve_id: str | None = None
    external_id: str = ""
    title: str = ""
    description: str = ""
    cve_pub_date: date | None = None
    severity: str = "Medium"
    components: str = ""
    scan_type: str = "dependency"
    tool: str = ""
    status: str = "New"
    mitigation: str = ""
    file_path: str = ""
    line: int | None = None
    cvss_vector: str = ""
    cvss_base_score: float | None = None
    adapted_score: float | None = None
    fixed_version: str = ""


class PreviewOut(BaseModel):
    scan_id: int | None = None
    rows: list[PreviewRow]
    warnings: list[str] = []
    duplicate_count: int = 0
    next_number: int = 1


class PreviewConfirm(BaseModel):
    scan_id: int | None = None
    rows: list[PreviewRow]
    patch: PatchIn | None = None
    plan: PlanIn | None = None
    plan_id: int | None = None


class ImportResult(BaseModel):
    created: list[str]
    skipped: int
    plan_ref: str | None = None


class CvssConfigIn(BaseModel):
    E: str = "X"
    RL: str = "X"
    RC: str = "X"
    CR: str = "X"
    IR: str = "X"
    AR: str = "X"
    MAV: str = "X"
    MAC: str = "X"
    MPR: str = "X"
    MUI: str = "X"
    MS: str = "X"
    MC: str = "X"
    MI: str = "X"
    MA: str = "X"


class CvssOverrideIn(BaseModel):
    E: str | None = None
    RL: str | None = None
    RC: str | None = None
    CR: str | None = None
    IR: str | None = None
    AR: str | None = None
    MAV: str | None = None
    MAC: str | None = None
    MPR: str | None = None
    MUI: str | None = None
    MS: str | None = None
    MC: str | None = None
    MI: str | None = None
    MA: str | None = None


class ScoreOut(BaseModel):
    base_score: float
    base_severity: str
    temporal_score: float
    adapted_score: float
    adapted_severity: str
    vector: str


class TokenIn(BaseModel):
    name: str
    project_id: int | None = None


class TokenOut(BaseModel):
    id: int
    name: str
    project_id: int | None
    prefix: str
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None
    token: str | None = None


class ReportRequest(BaseModel):
    project_id: int | None = None
    plan_id: int | None = None
    finding_ids: list[int] = []
    template: str = "default"
    output_format: str = "pdf"
    title: str = "Vulnerability report"
    document_code: str = ""
    version: str = "1.0"
    authors: str = ""
    software_version: str = ""
    analysis_date: date | None = None
    include_unreported_only: bool = False


class ReportJobOut(BaseModel):
    model_config = ORM
    id: int
    status: str
    template: str
    output_format: str
    error: str
    created_at: datetime
    finished_at: datetime | None
    download_url: str | None = None
    bundle_url: str | None = None


class DashboardOut(BaseModel):
    project_id: int | None
    by_severity: dict[str, int]
    by_status: dict[str, int]
    total: int
    without_plan: int
    overdue_plans: list[PlanOut]
    sla_breaches: list[FindingOut]
    recent_scans: list[ScanOut]
