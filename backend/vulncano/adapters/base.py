"""The single interface every scanner sits behind. One adapter is one file."""

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from pydantic import BaseModel

from ..manifests import ManifestResult, parse_manifest, parser_for


class ScannerError(RuntimeError):
    """Raised with a message the user can act on: what failed and what to do about it."""


class NotImplementedYet(ScannerError):
    """The adapter exists as a contribution target but does not run yet."""


@dataclass
class UploadedFile:
    name: str
    content: bytes

    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")


@dataclass
class ScanTarget:
    """Whatever the user handed over: files, an image reference, a path or a git url."""

    files: list[UploadedFile] = field(default_factory=list)
    image: str = ""
    path: str = ""
    git_url: str = ""

    def describe(self) -> str:
        if self.files:
            return ", ".join(item.name for item in self.files)
        return self.image or self.path or self.git_url or "empty target"

    def manifests(self) -> ManifestResult:
        """Every uploaded file a manifest parser recognises, merged into one dependency list."""
        merged = ManifestResult()
        for item in self.files:
            if parser_for(item.name) is None:
                merged.warnings.append(f"{item.name}: not a recognised manifest, ignored")
                continue
            merged.extend(parse_manifest(item.name, item.text()))
        if self.path:
            merged.extend(scan_directory(Path(self.path)))
        return merged


def scan_directory(root: Path) -> ManifestResult:
    merged = ManifestResult()
    if not root.exists():
        raise ScannerError(f"path {root} does not exist on the machine running Vulncano")
    candidates = [root] if root.is_file() else sorted(root.rglob("*"))
    for candidate in candidates:
        if not candidate.is_file() or parser_for(candidate.name) is None:
            continue
        if any(part in {"node_modules", ".git", "venv", ".venv"} for part in candidate.parts):
            continue
        merged.extend(parse_manifest(candidate.name, candidate.read_text(errors="replace")))
    if not merged.dependencies:
        merged.warnings.append(f"no supported manifest found under {root}")
    return merged


@dataclass
class RawResult:
    """Whatever the tool produced, kept verbatim so a scan can be re-parsed or attached to a report."""

    payload: bytes = b""
    content_type: str = "application/json"
    log: str = ""
    remote_id: str = ""


@dataclass
class NormalizedFinding:
    title: str
    cve_id: str | None = None
    external_id: str = ""
    description: str = ""
    severity: str = "Medium"
    components: list[str] = field(default_factory=list)
    scan_type: str = "dependency"
    tool: str = ""
    cve_pub_date: date | None = None
    cvss_vector: str = ""
    cvss_base_score: float | None = None
    fixed_version: str = ""
    mitigation: str = ""
    file_path: str = ""
    line: int | None = None
    references: list[str] = field(default_factory=list)

    def dedup_key(self) -> tuple:
        """A finding is the same one when the advisory and the affected artifact match."""
        identifier = (self.cve_id or self.external_id or self.title).strip().lower()
        return identifier, tuple(sorted(component.strip().lower() for component in self.components))


class ScannerAdapter:
    tool = ""
    label = ""
    config_schema: type[BaseModel] | None = None
    accepts: tuple[str, ...] = ()
    needs_credentials = False
    implemented = True
    install_hint = ""

    def validate(self, config) -> tuple[bool, str | None]:
        """Check credentials or binary availability. Returns (ok, message)."""
        raise NotImplementedError

    def run(self, config, target: ScanTarget) -> RawResult:
        raise NotImplementedError

    def parse(self, raw: RawResult) -> list[NormalizedFinding]:
        raise NotImplementedError


SEVERITY_ALIASES = {
    "critical": "Critical",
    "high": "High",
    "moderate": "Medium",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "informational": "Info",
    "negligible": "Info",
    "none": "Info",
    "unknown": "Info",
    "warning": "Medium",
    "error": "High",
    "note": "Info",
}


def normalize_severity(value: str | None, default: str = "Medium") -> str:
    if not value:
        return default
    return SEVERITY_ALIASES.get(str(value).strip().lower(), default)
