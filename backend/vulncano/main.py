from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__
from .adapters import NotImplementedYet, ScannerError
from .auth import require_user
from .config import get_settings
from .crypto import SecretKeyMissing
from .db import init_db
from .manifests import SUPPORTED, UnsupportedManifest
from .models import PLAN_STATUSES, SCAN_TYPES, SEVERITIES, STATUSES
from .routers import cvss, dump, findings, patches, plans, projects, reports, scanners, scans, tokens

app = FastAPI(
    title="Vulncano",
    version=__version__,
    description="Track and fix software vulnerabilities. Projects, findings, patches, plans.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

for module in (projects, findings, patches, plans, scanners, scans, cvss, reports, tokens, dump):
    app.include_router(module.router, dependencies=[Depends(require_user)])


@app.exception_handler(NotImplementedYet)
def under_development(request: Request, exc: NotImplementedYet):
    return JSONResponse(status_code=501, content={"detail": str(exc), "under_development": True})


@app.exception_handler(ScannerError)
def scanner_failed(request: Request, exc: ScannerError):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(UnsupportedManifest)
def bad_manifest(request: Request, exc: UnsupportedManifest):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(SecretKeyMissing)
def missing_key(request: Request, exc: SecretKeyMissing):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.on_event("startup")
def startup():
    init_db()


@app.get("/api/health")
def health():
    settings = get_settings()
    return {
        "status": "ok",
        "version": __version__,
        "auth_enabled": settings.auth_enabled,
        "database": settings.database_url.split("://", 1)[0],
    }


@app.get("/api/meta")
def meta():
    """Everything the frontend needs to build its dropdowns without hardcoding them."""
    return {
        "severities": list(SEVERITIES),
        "statuses": list(STATUSES),
        "scan_types": list(SCAN_TYPES),
        "plan_statuses": list(PLAN_STATUSES),
        "manifests": SUPPORTED,
    }
