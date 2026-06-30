from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.soc import Incident, SecurityEvent
from app.schemas.soc import AnalyzeResponse, IncidentRead, SecurityEventCreate, SecurityEventRead
from app.services.agent import SocAgent
from app.services.ml_detector import detector
from app.services.reporting import build_incident_title, format_markdown_report, should_create_incident

router = APIRouter()
agent = SocAgent()


@router.post("/events", response_model=AnalyzeResponse)
def ingest_event(payload: SecurityEventCreate, db: Session = Depends(get_db)) -> AnalyzeResponse:
    risk_score = detector.anomaly_score(payload)
    event = SecurityEvent(**payload.model_dump(), risk_score=risk_score)
    db.add(event)
    db.commit()
    db.refresh(event)

    incident = None
    if should_create_incident(event):
        event_read = SecurityEventRead.model_validate(event)
        summary, actions = agent.analyze(event_read)
        incident = Incident(
            event_id=event.id,
            title=build_incident_title(event),
            summary=summary,
            recommended_actions=actions,
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)

    return AnalyzeResponse(event=event, incident=incident)


@router.get("/events", response_model=list[SecurityEventRead])
def list_events(db: Session = Depends(get_db), limit: int = 100) -> list[SecurityEvent]:
    return list(db.scalars(select(SecurityEvent).order_by(desc(SecurityEvent.timestamp)).limit(limit)))


@router.get("/incidents", response_model=list[IncidentRead])
def list_incidents(db: Session = Depends(get_db), limit: int = 100) -> list[Incident]:
    return list(db.scalars(select(Incident).order_by(desc(Incident.created_at)).limit(limit)))


@router.get("/incidents/{incident_id}/report")
def incident_report(incident_id: int, db: Session = Depends(get_db)) -> dict[str, str]:
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"report": format_markdown_report(incident)}


@router.post("/detector/train")
def train_detector(db: Session = Depends(get_db)) -> dict[str, str | int]:
    events = db.scalars(select(SecurityEvent).order_by(SecurityEvent.timestamp)).all()
    payloads = [
        SecurityEventCreate(
            source=e.source,
            host=e.host,
            username=e.username,
            src_ip=e.src_ip,
            event_type=e.event_type,
            severity=e.severity,
            message=e.message,
        )
        for e in events
    ]
    detector.fit(payloads)
    return {"status": "trained" if detector.trained else "need at least 10 events", "events": len(payloads)}
