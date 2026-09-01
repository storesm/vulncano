from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters import ADAPTERS, NotImplementedYet, ScannerError, describe_adapters, get_adapter
from ..crypto import SecretKeyMissing, decrypt_config, encrypt_config
from ..db import get_session
from ..models import ScannerConfig
from ..schemas import ScannerConfigIn, ScannerConfigOut

router = APIRouter(prefix="/api/scanners", tags=["scanners"])


def _secret_fields(tool: str) -> set[str]:
    adapter = ADAPTERS.get(tool)
    if adapter is None or adapter.config_schema is None:
        return set()
    properties = adapter.config_schema.model_json_schema().get("properties") or {}
    return {name for name, spec in properties.items() if spec.get("secret")}


def _to_out(config: ScannerConfig) -> ScannerConfigOut:
    stored = decrypt_config(config.config_enc)
    secrets = _secret_fields(config.tool)
    visible = {key: value for key, value in stored.items() if key not in secrets}
    return ScannerConfigOut(
        id=config.id,
        project_id=config.project_id,
        tool=config.tool,
        name=config.name,
        enabled=config.enabled,
        config=visible,
        credential_set=any(stored.get(name) for name in secrets),
        created_at=config.created_at,
    )


@router.get("/adapters", response_model=list[dict])
def list_adapters():
    """Everything the settings screen needs to render a form for each scanner."""
    return describe_adapters()


@router.get("/configs", response_model=list[ScannerConfigOut])
def list_configs(project_id: int | None = None, session: Session = Depends(get_session)):
    query = select(ScannerConfig)
    if project_id:
        query = query.where(
            (ScannerConfig.project_id == project_id) | (ScannerConfig.project_id.is_(None))
        )
    return [_to_out(config) for config in session.scalars(query.order_by(ScannerConfig.id)).all()]


@router.post("/configs", response_model=ScannerConfigOut, status_code=201)
def create_config(payload: ScannerConfigIn, session: Session = Depends(get_session)):
    if payload.tool not in ADAPTERS:
        raise HTTPException(400, f"unknown scanner {payload.tool}")
    try:
        config = ScannerConfig(
            project_id=payload.project_id,
            tool=payload.tool,
            name=payload.name,
            enabled=payload.enabled,
            config_enc=encrypt_config(payload.config),
        )
    except SecretKeyMissing as exc:
        raise HTTPException(400, str(exc)) from exc
    session.add(config)
    session.commit()
    return _to_out(config)


@router.put("/configs/{config_id}", response_model=ScannerConfigOut)
def update_config(config_id: int, payload: ScannerConfigIn, session: Session = Depends(get_session)):
    config = session.get(ScannerConfig, config_id)
    if config is None:
        raise HTTPException(404, f"scanner config {config_id} not found")
    stored = decrypt_config(config.config_enc)
    merged = dict(stored)
    # a blank secret in the form means keep the stored one, the API never sends it back to be re-posted
    for key, value in payload.config.items():
        if key in _secret_fields(config.tool) and value == "":
            continue
        merged[key] = value
    config.name = payload.name
    config.enabled = payload.enabled
    config.project_id = payload.project_id
    config.config_enc = encrypt_config(merged)
    session.commit()
    return _to_out(config)


@router.delete("/configs/{config_id}", status_code=204)
def delete_config(config_id: int, session: Session = Depends(get_session)):
    config = session.get(ScannerConfig, config_id)
    if config is None:
        raise HTTPException(404, f"scanner config {config_id} not found")
    session.delete(config)
    session.commit()


@router.post("/configs/{config_id}/test", response_model=dict)
def test_credentials(config_id: int, session: Session = Depends(get_session)):
    config = session.get(ScannerConfig, config_id)
    if config is None:
        raise HTTPException(404, f"scanner config {config_id} not found")
    adapter = get_adapter(config.tool)
    try:
        ok, message = adapter.validate(decrypt_config(config.config_enc))
    except NotImplementedYet as exc:
        raise HTTPException(501, str(exc)) from exc
    except ScannerError as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": ok, "message": message}
