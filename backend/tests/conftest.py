import os
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture()
def database(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNCANO_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("VULNCANO_DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("VULNCANO_SECRET_KEY", "test-key-not-a-real-one")

    from vulncano.config import get_settings
    from vulncano.db import init_db, reset_engine

    get_settings.cache_clear()
    reset_engine()
    init_db()
    yield
    reset_engine()
    get_settings.cache_clear()


@pytest.fixture()
def session(database):
    from vulncano.db import get_sessionmaker

    handle = get_sessionmaker()()
    try:
        yield handle
    finally:
        handle.close()


@pytest.fixture()
def client(database):
    from fastapi.testclient import TestClient

    from vulncano.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def project(session):
    from vulncano.models import Project

    item = Project(key="BACKEND", name="Backend service")
    session.add(item)
    session.commit()
    return item


def fixture_bytes(*parts) -> bytes:
    return (FIXTURES.joinpath(*parts)).read_bytes()


def fixture_text(*parts) -> str:
    return (FIXTURES.joinpath(*parts)).read_text()


os.environ.setdefault("VULNCANO_SECRET_KEY", "test-key-not-a-real-one")
