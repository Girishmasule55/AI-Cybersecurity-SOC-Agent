from datetime import datetime

from pydantic import BaseModel, Field


class SecurityEventCreate(BaseModel):
    source: str = Field(examples=["auth.log"])
    host: str = Field(examples=["web-01"])
    username: str | None = Field(default=None, examples=["admin"])
    src_ip: str | None = Field(default=None, examples=["185.220.101.1"])
    event_type: str = Field(examples=["login_failed"])
    severity: str = Field(default="low", examples=["medium"])
    message: str


class SecurityEventRead(SecurityEventCreate):
    id: int
    timestamp: datetime
    risk_score: float

    class Config:
        from_attributes = True


class IncidentRead(BaseModel):
    id: int
    event_id: int
    status: str
    title: str
    summary: str
    recommended_actions: str
    created_at: datetime

    class Config:
        from_attributes = True


class AnalyzeResponse(BaseModel):
    event: SecurityEventRead
    incident: IncidentRead | None = None
