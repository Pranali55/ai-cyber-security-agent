from fastapi import FastAPI

import detectors
import enrich
from schemas import AnalysisResponse, EmailRequest, LogRequest, PasswordRequest, UrlRequest

app = FastAPI(title="AI Cyber Security Agent", description="Defensive threat analysis: logs, URLs, emails, passwords")


@app.get("/health")
def health():
    return {"status": "ok", "service": "ai-cyber-security-agent"}


@app.post("/analyze/logs", response_model=AnalysisResponse)
async def logs(req: LogRequest):
    return await enrich.refine("log", detectors.analyze_logs(req.content))


@app.post("/analyze/url", response_model=AnalysisResponse)
async def url(req: UrlRequest):
    return await enrich.refine("URL", detectors.analyze_url(req.url))


@app.post("/analyze/email", response_model=AnalysisResponse)
async def email(req: EmailRequest):
    return await enrich.refine("email", detectors.analyze_email(req.sender or "", req.subject or "", req.body))


@app.post("/analyze/password", response_model=AnalysisResponse)
async def password(req: PasswordRequest):
    return await enrich.refine("password", await detectors.analyze_password(req.password))
