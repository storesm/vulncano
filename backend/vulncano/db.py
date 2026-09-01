from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings
from .models import Base, Counter

REF_PREFIXES = {"findings": "VLN", "patches": "PATCH", "plans": "PLAN", "scans": "SCAN"}

_engine = None
_SessionLocal = None


def _connect_args(url: str) -> dict:
    if url.startswith("sqlite"):
        return {"check_same_thread": False}
    return {}


def _enable_sqlite_foreign_keys(dbapi_connection, _record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def get_engine():
    global _engine, _SessionLocal
    if _engine is None:
        url = get_settings().database_url
        _engine = create_engine(url, connect_args=_connect_args(url), pool_pre_ping=True, future=True)
        if url.startswith("sqlite"):
            # foreign keys are off by default on sqlite and the cascades depend on them
            event.listen(_engine, "connect", _enable_sqlite_foreign_keys)
        _SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)
    return _engine


def get_sessionmaker():
    get_engine()
    return _SessionLocal


def init_db() -> None:
    Base.metadata.create_all(get_engine())


def reset_engine() -> None:
    """Drop the cached engine so a process can switch database url (tests, CLI flags)."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None


@contextmanager
def session_scope() -> Iterator[Session]:
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_session() -> Iterator[Session]:
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()


def next_refs(session: Session, table: str, count: int) -> list[str]:
    """Reserve count refs for a table and return them formatted, for example VLN-0007."""
    prefix = REF_PREFIXES[table]
    lockable = session.get_bind().dialect.name != "sqlite"
    counter = session.get(Counter, table, with_for_update=lockable)
    if counter is None:
        counter = Counter(name=table, value=0)
        session.add(counter)
        session.flush()
    start = counter.value
    counter.value = start + count
    session.flush()
    return [f"{prefix}-{n:04d}" for n in range(start + 1, start + count + 1)]


def peek_refs(session: Session, table: str, count: int) -> list[str]:
    """Same numbering as next_refs but without consuming anything, used by the preview table."""
    prefix = REF_PREFIXES[table]
    current = session.scalar(select(Counter.value).where(Counter.name == table)) or 0
    return [f"{prefix}-{n:04d}" for n in range(current + 1, current + count + 1)]
