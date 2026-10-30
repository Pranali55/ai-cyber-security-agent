from typing import List, Optional
from pydantic import BaseModel


class Finding(BaseModel):
    type: str
    severity: str  # Critical, High, Medium, Low, Info
    description: str
    evidence: Optional[str] = None


class AnalysisResponse(BaseModel):
    severity: str
    risk_score: int
    summary: str
    findings: List[Finding]
    recommendations: List[str]


class LogRequest(BaseModel):
    content: str


class UrlRequest(BaseModel):
    url: str


class EmailRequest(BaseModel):
    sender: Optional[str] = None
    subject: Optional[str] = None
    body: str


class PasswordRequest(BaseModel):
    password: str
