"""Backup and restore as plain SQL. Portable between SQLite and MySQL because only INSERT
statements are emitted, the schema comes from the create script."""

from datetime import date, datetime

from sqlalchemy import delete, select, text
from sqlalchemy.orm import Session

from .models import Base

HEADER = "-- Vulncano dump\n-- restore with: vulncano restore dump.sql\n"


def _literal(value) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, datetime):
        return "'" + value.isoformat(sep=" ") + "'"
    if isinstance(value, date):
        return "'" + value.isoformat() + "'"
    return "'" + str(value).replace("\\", "\\\\").replace("'", "''") + "'"


def dump_sql(session: Session) -> str:
    lines = [HEADER]
    for table in Base.metadata.sorted_tables:
        rows = session.execute(select(table)).mappings().all()
        if not rows:
            continue
        columns = ", ".join(table.columns.keys())
        lines.append(f"\n-- {table.name} ({len(rows)} rows)")
        for row in rows:
            values = ", ".join(_literal(row[column]) for column in table.columns.keys())
            lines.append(f"INSERT INTO {table.name} ({columns}) VALUES ({values});")
    return "\n".join(lines) + "\n"


def restore_sql(session: Session, sql: str) -> int:
    """Wipe and reload. The whole thing runs in one transaction, a bad line rolls everything back."""
    for table in reversed(Base.metadata.sorted_tables):
        session.execute(delete(table))
    executed = 0
    statement = []
    for line in sql.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            continue
        statement.append(line)
        if stripped.endswith(";"):
            session.execute(text("\n".join(statement).rstrip(";")))
            statement = []
            executed += 1
    return executed
