from app.models.soc import Incident, SecurityEvent


def build_incident_title(event: SecurityEvent) -> str:
    return f"{event.severity.upper()} {event.event_type} on {event.host}"


def should_create_incident(event: SecurityEvent) -> bool:
    return event.risk_score >= 60


def format_markdown_report(incident: Incident) -> str:
    event = incident.event
    return f"""# Incident #{incident.id}: {incident.title}

Status: {incident.status}
Risk score: {event.risk_score:.0f}/100
Host: {event.host}
Source IP: {event.src_ip or "unknown"}
User: {event.username or "unknown"}

## Summary

{incident.summary}

## Recommended Actions

{incident.recommended_actions}

## Raw Event

{event.message}
"""
