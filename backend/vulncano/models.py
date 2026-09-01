from datetime import date, datetime

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
STATUSES = ("New", "Confirmed", "False positive", "Risk accepted", "Fixed")
SCAN_TYPES = ("dependency", "static", "container", "secret", "license")
PLAN_STATUSES = ("Draft", "Approved", "In progress", "Done", "Cancelled")
SCAN_STATUSES = ("queued", "running", "parsed", "imported", "failed")

CVSS_METRICS = ("E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA")

DEFAULT_SLA = {"Critical": 7, "High": 30, "Medium": 90, "Low": 180, "Info": 365}


class Base(DeclarativeBase):
    pass


def _metric_column():
    return mapped_column(String(2), default="X", nullable=False)


class Counter(Base):
    """Sequence source for the human readable refs, so deletions never recycle a number."""

    __tablename__ = "counters"

    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    value: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    sla_critical: Mapped[int] = mapped_column(Integer, default=DEFAULT_SLA["Critical"])
    sla_high: Mapped[int] = mapped_column(Integer, default=DEFAULT_SLA["High"])
    sla_medium: Mapped[int] = mapped_column(Integer, default=DEFAULT_SLA["Medium"])
    sla_low: Mapped[int] = mapped_column(Integer, default=DEFAULT_SLA["Low"])
    sla_info: Mapped[int] = mapped_column(Integer, default=DEFAULT_SLA["Info"])
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    findings: Mapped[list["Finding"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    plans: Mapped[list["Plan"]] = relationship(back_populates="project", cascade="all, delete-orphan")

    def sla_days(self, severity: str) -> int:
        return {
            "Critical": self.sla_critical,
            "High": self.sla_high,
            "Medium": self.sla_medium,
            "Low": self.sla_low,
            "Info": self.sla_info,
        }.get(severity, self.sla_info)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ref: Mapped[str] = mapped_column(String(16), unique=True, nullable=False)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    cve_id: Mapped[str | None] = mapped_column(String(32), index=True)
    external_id: Mapped[str] = mapped_column(String(120), default="")
    title: Mapped[str] = mapped_column(String(500), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    cve_pub_date: Mapped[date | None] = mapped_column(Date)
    severity: Mapped[str] = mapped_column(String(16), default="Medium", index=True)
    components: Mapped[str] = mapped_column(Text, default="")
    scan_type: Mapped[str] = mapped_column(String(16), default="dependency", index=True)
    tool: Mapped[str] = mapped_column(String(40), default="", index=True)
    origin: Mapped[str] = mapped_column(String(120), default="Manually")
    status: Mapped[str] = mapped_column(String(20), default="New", index=True)
    mitigation: Mapped[str] = mapped_column(Text, default="")
    file_path: Mapped[str] = mapped_column(String(500), default="")
    line: Mapped[int | None] = mapped_column(Integer)
    reported: Mapped[bool] = mapped_column(Boolean, default=False)

    cvss_vector: Mapped[str] = mapped_column(String(200), default="")
    cvss_base_score: Mapped[float | None] = mapped_column(Float)
    cvss_source: Mapped[str] = mapped_column(String(40), default="")
    cvss_fetched_at: Mapped[datetime | None] = mapped_column(DateTime)
    adapted_score: Mapped[float | None] = mapped_column(Float)
    adapted_vector: Mapped[str] = mapped_column(String(400), default="")

    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    regressed_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())

    project: Mapped[Project] = relationship(back_populates="findings")
    patch: Mapped["Patch | None"] = relationship(
        back_populates="finding", cascade="all, delete-orphan", uselist=False
    )
    cvss_override: Mapped["CvssFindingOverride | None"] = relationship(
        back_populates="finding", cascade="all, delete-orphan", uselist=False
    )

    @property
    def component_list(self) -> list[str]:
        return [line.strip() for line in self.components.splitlines() if line.strip()]


class Patch(Base):
    __tablename__ = "patches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ref: Mapped[str] = mapped_column(String(16), unique=True, nullable=False)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    plan_id: Mapped[int | None] = mapped_column(ForeignKey("plans.id", ondelete="SET NULL"), index=True)
    fixed_version: Mapped[str] = mapped_column(String(120), default="")
    patch_pub_date: Mapped[date | None] = mapped_column(Date)
    functional_impact: Mapped[str] = mapped_column(Text, default="")
    operational_impact: Mapped[str] = mapped_column(Text, default="")
    regression_tests: Mapped[str] = mapped_column(Text, default="")
    schedule: Mapped[str] = mapped_column(String(200), default="")
    applied_at: Mapped[date | None] = mapped_column(Date)
    comments: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    finding: Mapped[Finding] = relationship(back_populates="patch")
    plan: Mapped["Plan | None"] = relationship(back_populates="patches")


class Plan(Base):
    __tablename__ = "plans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ref: Mapped[str] = mapped_column(String(16), unique=True, nullable=False)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    target_version: Mapped[str] = mapped_column(String(120), default="")
    target_date: Mapped[date | None] = mapped_column(Date)
    owner: Mapped[str] = mapped_column(String(120), default="")
    status: Mapped[str] = mapped_column(String(20), default="Draft")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    project: Mapped[Project] = relationship(back_populates="plans")
    patches: Mapped[list[Patch]] = relationship(back_populates="plan")


class CvssProjectConfig(Base):
    __tablename__ = "cvss_project_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    E: Mapped[str] = _metric_column()
    RL: Mapped[str] = _metric_column()
    RC: Mapped[str] = _metric_column()
    CR: Mapped[str] = _metric_column()
    IR: Mapped[str] = _metric_column()
    AR: Mapped[str] = _metric_column()
    MAV: Mapped[str] = _metric_column()
    MAC: Mapped[str] = _metric_column()
    MPR: Mapped[str] = _metric_column()
    MUI: Mapped[str] = _metric_column()
    MS: Mapped[str] = _metric_column()
    MC: Mapped[str] = _metric_column()
    MI: Mapped[str] = _metric_column()
    MA: Mapped[str] = _metric_column()


class CvssFindingOverride(Base):
    __tablename__ = "cvss_finding_overrides"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    E: Mapped[str | None] = mapped_column(String(2))
    RL: Mapped[str | None] = mapped_column(String(2))
    RC: Mapped[str | None] = mapped_column(String(2))
    CR: Mapped[str | None] = mapped_column(String(2))
    IR: Mapped[str | None] = mapped_column(String(2))
    AR: Mapped[str | None] = mapped_column(String(2))
    MAV: Mapped[str | None] = mapped_column(String(2))
    MAC: Mapped[str | None] = mapped_column(String(2))
    MPR: Mapped[str | None] = mapped_column(String(2))
    MUI: Mapped[str | None] = mapped_column(String(2))
    MS: Mapped[str | None] = mapped_column(String(2))
    MC: Mapped[str | None] = mapped_column(String(2))
    MI: Mapped[str | None] = mapped_column(String(2))
    MA: Mapped[str | None] = mapped_column(String(2))

    finding: Mapped[Finding] = relationship(back_populates="cvss_override")


class ScannerConfig(Base):
    __tablename__ = "scanner_configs"
    __table_args__ = (UniqueConstraint("project_id", "name", name="uq_scanner_project_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int | None] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    tool: Mapped[str] = mapped_column(String(40), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config_enc: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ref: Mapped[str] = mapped_column(String(16), unique=True, nullable=False)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    scanner_config_id: Mapped[int | None] = mapped_column(
        ForeignKey("scanner_configs.id", ondelete="SET NULL")
    )
    tool: Mapped[str] = mapped_column(String(40), nullable=False)
    source: Mapped[str] = mapped_column(String(500), default="")
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    remote_id: Mapped[str] = mapped_column(String(200), default="")
    raw_path: Mapped[str] = mapped_column(String(500), default="")
    parsed_json: Mapped[str] = mapped_column(Text, default="")
    log: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str] = mapped_column(Text, default="")
    parsed_count: Mapped[int] = mapped_column(Integer, default=0)
    imported_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    project_id: Mapped[int | None] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime)


class ReportJob(Base):
    __tablename__ = "report_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    status: Mapped[str] = mapped_column(String(16), default="queued")
    template: Mapped[str] = mapped_column(String(120), default="default")
    output_format: Mapped[str] = mapped_column(String(8), default="pdf")
    params: Mapped[str] = mapped_column(Text, default="{}")
    finding_ids: Mapped[str] = mapped_column(Text, default="")
    output_path: Mapped[str] = mapped_column(String(500), default="")
    bundle_path: Mapped[str] = mapped_column(String(500), default="")
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
