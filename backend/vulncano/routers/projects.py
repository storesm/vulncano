from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_session
from ..models import Finding, Project
from ..schemas import ProjectIn, ProjectOut
from ..scoring import project_config, recompute_project
from ..services import OPEN_STATUSES

router = APIRouter(prefix="/api/projects", tags=["projects"])


def _to_out(session: Session, project: Project) -> ProjectOut:
    total = session.scalar(
        select(func.count(Finding.id)).where(Finding.project_id == project.id)
    ) or 0
    open_count = session.scalar(
        select(func.count(Finding.id)).where(
            Finding.project_id == project.id, Finding.status.in_(OPEN_STATUSES)
        )
    ) or 0
    return ProjectOut.model_validate(project).model_copy(
        update={"finding_count": total, "open_count": open_count}
    )


@router.get("", response_model=list[ProjectOut])
def list_projects(session: Session = Depends(get_session)):
    projects = session.scalars(select(Project).order_by(Project.key)).all()
    return [_to_out(session, project) for project in projects]


@router.post("", response_model=ProjectOut, status_code=201)
def create_project(payload: ProjectIn, session: Session = Depends(get_session)):
    if session.scalar(select(Project).where(Project.key == payload.key)):
        raise HTTPException(409, f"project key {payload.key} is already taken")
    project = Project(**payload.model_dump())
    session.add(project)
    session.commit()
    project_config(session, project.id)
    session.commit()
    return _to_out(session, project)


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(project_id: int, session: Session = Depends(get_session)):
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(404, f"project {project_id} not found")
    return _to_out(session, project)


@router.put("/{project_id}", response_model=ProjectOut)
def update_project(project_id: int, payload: ProjectIn, session: Session = Depends(get_session)):
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(404, f"project {project_id} not found")
    clash = session.scalar(select(Project).where(Project.key == payload.key, Project.id != project_id))
    if clash:
        raise HTTPException(409, f"project key {payload.key} is already taken")
    for field, value in payload.model_dump().items():
        setattr(project, field, value)
    recompute_project(session, project.id)
    session.commit()
    return _to_out(session, project)


@router.delete("/{project_id}", status_code=204)
def delete_project(project_id: int, session: Session = Depends(get_session)):
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(404, f"project {project_id} not found")
    session.delete(project)
    session.commit()
