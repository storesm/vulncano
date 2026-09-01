from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_session, next_refs
from ..models import Patch, Plan, Project
from ..schemas import FindingOut, IdList, PlanIn, PlanOut, PlanUpdate
from ..services import attach_findings_to_plan, close_plan, finding_out, plan_out

router = APIRouter(prefix="/api/plans", tags=["plans"])


def _load(session: Session, plan_id: int) -> Plan:
    plan = session.get(Plan, plan_id)
    if plan is None:
        raise HTTPException(404, f"plan {plan_id} not found")
    return plan


@router.get("", response_model=list[PlanOut])
def list_plans(project_id: int | None = None, session: Session = Depends(get_session)):
    query = select(Plan)
    if project_id:
        query = query.where(Plan.project_id == project_id)
    return [plan_out(session, plan) for plan in session.scalars(query.order_by(Plan.id.desc())).all()]


@router.post("", response_model=PlanOut, status_code=201)
def create_plan(payload: PlanIn, session: Session = Depends(get_session)):
    if session.get(Project, payload.project_id) is None:
        raise HTTPException(404, f"project {payload.project_id} not found")
    data = payload.model_dump(exclude={"finding_ids"})
    plan = Plan(ref=next_refs(session, "plans", 1)[0], **data)
    session.add(plan)
    session.flush()
    attach_findings_to_plan(session, plan, payload.finding_ids)
    session.commit()
    return plan_out(session, plan)


@router.get("/{plan_id}", response_model=PlanOut)
def get_plan(plan_id: int, session: Session = Depends(get_session)):
    return plan_out(session, _load(session, plan_id))


@router.put("/{plan_id}", response_model=PlanOut)
def update_plan(plan_id: int, payload: PlanUpdate, session: Session = Depends(get_session)):
    plan = _load(session, plan_id)
    fields = payload.model_dump(exclude_unset=True)
    closing = fields.get("status") == "Done" and plan.status != "Done"
    for field, value in fields.items():
        setattr(plan, field, value)
    if closing:
        close_plan(session, plan)
    session.commit()
    return plan_out(session, plan)


@router.delete("/{plan_id}", status_code=204)
def delete_plan(plan_id: int, session: Session = Depends(get_session)):
    plan = _load(session, plan_id)
    for patch in session.scalars(select(Patch).where(Patch.plan_id == plan.id)).all():
        patch.plan_id = None
    session.delete(plan)
    session.commit()


@router.get("/{plan_id}/findings", response_model=list[FindingOut])
def plan_findings(plan_id: int, session: Session = Depends(get_session)):
    plan = _load(session, plan_id)
    patches = session.scalars(select(Patch).where(Patch.plan_id == plan.id)).all()
    return [finding_out(patch.finding, patch.finding.project) for patch in patches]


@router.post("/{plan_id}/findings", response_model=PlanOut)
def add_findings(plan_id: int, payload: IdList, session: Session = Depends(get_session)):
    plan = _load(session, plan_id)
    attach_findings_to_plan(session, plan, payload.ids)
    session.commit()
    return plan_out(session, plan)


@router.delete("/{plan_id}/findings/{finding_id}", response_model=PlanOut)
def remove_finding(plan_id: int, finding_id: int, session: Session = Depends(get_session)):
    plan = _load(session, plan_id)
    patch = session.scalar(select(Patch).where(Patch.plan_id == plan.id, Patch.finding_id == finding_id))
    if patch is None:
        raise HTTPException(404, f"finding {finding_id} is not part of {plan.ref}")
    patch.plan_id = None
    session.commit()
    return plan_out(session, plan)
