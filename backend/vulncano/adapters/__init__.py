"""Adapter registry. Adding a scanner means adding one file here and one line below."""

from .base import (
    NormalizedFinding,
    NotImplementedYet,
    RawResult,
    ScannerAdapter,
    ScannerError,
    ScanTarget,
    UploadedFile,
)
from .checkmarx import CheckmarxAdapter
from .generic import (
    CycloneDxAdapter,
    DependencyCheckAdapter,
    GrypeAdapter,
    SarifAdapter,
    SpreadsheetAdapter,
    sniff_format,
)
from .osv import OsvAdapter
from .scanoss import ScanossAdapter
from .trivy import TrivyAdapter

ADAPTERS = {
    adapter.tool: adapter()
    for adapter in (
        OsvAdapter,
        ScanossAdapter,
        TrivyAdapter,
        CheckmarxAdapter,
        SarifAdapter,
        CycloneDxAdapter,
        GrypeAdapter,
        DependencyCheckAdapter,
        SpreadsheetAdapter,
    )
}

IMPORTERS = ("sarif", "cyclonedx", "grype", "dependency-check", "spreadsheet")

__all__ = [
    "ADAPTERS",
    "IMPORTERS",
    "NormalizedFinding",
    "NotImplementedYet",
    "RawResult",
    "ScanTarget",
    "ScannerAdapter",
    "ScannerError",
    "UploadedFile",
    "get_adapter",
    "sniff_format",
]


def get_adapter(tool: str) -> ScannerAdapter:
    adapter = ADAPTERS.get(tool)
    if adapter is None:
        raise ScannerError(f"unknown scanner {tool}. Available: {', '.join(sorted(ADAPTERS))}")
    return adapter


def describe_adapters() -> list[dict]:
    """What the settings screen renders: one entry per adapter with its config form schema."""
    entries = []
    for adapter in ADAPTERS.values():
        schema = adapter.config_schema.model_json_schema() if adapter.config_schema else {}
        secret_fields = [
            name for name, spec in (schema.get("properties") or {}).items() if spec.get("secret")
        ]
        entries.append(
            {
                "tool": adapter.tool,
                "label": adapter.label,
                "accepts": list(adapter.accepts),
                "needs_credentials": adapter.needs_credentials,
                "implemented": adapter.implemented,
                "install_hint": adapter.install_hint,
                "is_importer": adapter.tool in IMPORTERS,
                "schema": schema,
                "secret_fields": secret_fields,
            }
        )
    return entries
