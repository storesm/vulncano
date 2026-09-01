"""Background work. A scan runs in a daemon thread and writes its progress to the database, so
the frontend only ever polls a row. No broker, no worker process to babysit."""

import json
import threading
import traceback
from dataclasses import asdict, fields
from datetime import date, datetime

from .adapters import NormalizedFinding, ScanTarget, ScannerError, get_adapter
from .config import get_settings
from .db import session_scope
from .models import Scan

FINDING_FIELDS = {field.name for field in fields(NormalizedFinding)}


def serialize_findings(findings: list[NormalizedFinding]) -> str:
    rows = []
    for finding in findings:
        data = asdict(finding)
        if data.get("cve_pub_date"):
            data["cve_pub_date"] = data["cve_pub_date"].isoformat()
        rows.append(data)
    return json.dumps(rows)


def deserialize_findings(blob: str) -> list[NormalizedFinding]:
    findings = []
    for row in json.loads(blob or "[]"):
        data = {key: value for key, value in row.items() if key in FINDING_FIELDS}
        if data.get("cve_pub_date"):
            data["cve_pub_date"] = date.fromisoformat(data["cve_pub_date"])
        findings.append(NormalizedFinding(**data))
    return findings


def append_log(scan: Scan, text: str) -> None:
    if not text:
        return
    scan.log = (scan.log + "\n" + text).strip()[-20000:]


def run_scan(scan_id: int, config: dict, target: ScanTarget) -> None:
    """Run one scan up to the parsed state. Importing stays a separate, explicit user action."""
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        session.commit()

        adapter = get_adapter(scan.tool)
        try:
            raw = adapter.run(config, target)
            append_log(scan, raw.log)
            if raw.payload:
                path = get_settings().scan_dir / f"{scan.ref}.raw"
                path.write_bytes(raw.payload)
                scan.raw_path = str(path)
            scan.remote_id = raw.remote_id
            findings = adapter.parse(raw)
            scan.parsed_json = serialize_findings(findings)
            scan.parsed_count = len(findings)
            scan.status = "parsed"
            append_log(scan, f"parsed {len(findings)} findings")
        except ScannerError as exc:
            scan.status = "failed"
            scan.error = str(exc)
            append_log(scan, f"failed: {exc}")
        except Exception as exc:
            scan.status = "failed"
            scan.error = f"{type(exc).__name__}: {exc}"
            append_log(scan, traceback.format_exc()[-4000:])
        finally:
            scan.finished_at = datetime.utcnow()


def start_scan(scan_id: int, config: dict, target: ScanTarget) -> None:
    threading.Thread(target=run_scan, args=(scan_id, config, target), daemon=True).start()
