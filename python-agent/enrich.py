import json
import os

from openai import AsyncOpenAI

from schemas import AnalysisResponse

_client = None


def _get_client():
    global _client
    key = os.getenv("OPENAI_API_KEY", "").strip()
    if not key:
        return None
    if _client is None:
        _client = AsyncOpenAI(api_key=key)
    return _client


async def refine(kind: str, resp: AnalysisResponse) -> AnalysisResponse:
    """Optionally let an LLM write a clearer summary and remediation steps.
    Only finding types/descriptions are sent, never raw logs, evidence or passwords."""
    client = _get_client()
    if client is None or not resp.findings:
        return resp
    brief = [{"type": f.type, "severity": f.severity, "description": f.description} for f in resp.findings[:15]]
    prompt = (
        f"You are a SOC analyst. These findings come from a {kind} analysis (risk {resp.risk_score}/100):\n"
        f"{json.dumps(brief)}\n\n"
        'Return JSON: {"summary": "2-3 sentence plain-English assessment", '
        '"recommendations": ["up to 6 concise, defensive, actionable steps"]}'
    )
    try:
        r = await client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500,
            response_format={"type": "json_object"},
        )
        data = json.loads(r.choices[0].message.content or "{}")
        if data.get("summary"):
            resp.summary = str(data["summary"])
        recs = [str(x) for x in data.get("recommendations", []) if x]
        if recs:
            resp.recommendations = recs[:6]
    except Exception:
        pass  # keep the rule-based result
    return resp
