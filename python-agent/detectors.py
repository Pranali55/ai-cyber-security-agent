import hashlib
import ipaddress
import math
import re
from collections import Counter, defaultdict
from typing import List, Tuple
from urllib.parse import urlparse

import httpx

from schemas import AnalysisResponse, Finding

SEV_WEIGHT = {"Critical": 40, "High": 25, "Medium": 10, "Low": 3, "Info": 0}

RECOMMENDATIONS = {
    "brute_force": "Enable account lockout or rate limiting, require MFA, and block the offending IPs at the firewall.",
    "possible_compromise": "Treat the account as compromised: reset credentials, revoke sessions and review activity after the successful login.",
    "sql_injection": "Use parameterized queries, validate input server-side and enable WAF rules for SQL injection.",
    "xss": "Encode output, sanitize user input and set a strict Content-Security-Policy header.",
    "path_traversal": "Normalize and validate file paths; never build file paths from raw user input.",
    "scanner": "Block known scanner user agents and rate-limit clients that generate many errors.",
    "sensitive_probe": "Make sure .env, .git and admin panels are not publicly reachable; restrict admin areas by IP or VPN.",
    "ip_host": "Do not trust links that use a raw IP address instead of a domain name.",
    "brand_impersonation": "Do not enter credentials. Open the official site by typing its address yourself.",
    "suspicious_url": "Treat this link as untrusted and verify it with the sender through another channel.",
    "phishing_language": "Do not reply or click. Report the message to your security team or email provider.",
    "dangerous_attachment": "Do not open the attachment. Scan it in a sandbox or delete it.",
    "weak_password": "Use a unique passphrase of 14+ characters and store it in a password manager.",
    "common_password": "Change this password immediately; it appears on common password lists.",
    "breached_password": "This password appeared in known data breaches. Stop using it everywhere and enable MFA.",
}


def score_to_severity(score: int, has_findings: bool) -> str:
    if score >= 70:
        return "Critical"
    if score >= 40:
        return "High"
    if score >= 15:
        return "Medium"
    return "Low" if has_findings else "Info"


def finalize(kind: str, findings: List[Finding], clean_message: str) -> AnalysisResponse:
    real = [f for f in findings if f.severity != "Info"]
    score = min(100, sum(SEV_WEIGHT.get(f.severity, 0) for f in findings))
    severity = score_to_severity(score, bool(real))

    recs: List[str] = []
    for f in findings:
        rec = RECOMMENDATIONS.get(f.type)
        if rec and rec not in recs:
            recs.append(rec)

    if real:
        top = ", ".join(sorted({f.type.replace("_", " ") for f in real})[:4])
        summary = f"{kind} analysis found {len(real)} issue(s) (risk {score}/100). Main concerns: {top}."
    else:
        summary = clean_message
    return AnalysisResponse(
        severity=severity, risk_score=score, summary=summary, findings=findings, recommendations=recs
    )


# ---------------------------------------------------------------- LOGS
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FAIL_RE = re.compile(r"failed password|authentication failure|invalid user|login failed|failed login|unauthorized|\s401\s", re.I)
ACCEPT_RE = re.compile(r"accepted password|login successful|successful login", re.I)
SQLI_RE = re.compile(
    r"(union(\s|\+|%20)+select|or(\s|\+|%20)+1(\s|\+|%20)*=(\s|\+|%20)*1|information_schema|sleep\(\d+\)|drop(\s|\+|%20)+table|'\s*or\s*'1'\s*=\s*'1)",
    re.I,
)
XSS_RE = re.compile(r"(<script|%3cscript|onerror\s*=|javascript:)", re.I)
TRAV_RE = re.compile(r"(\.\./|\.\.%2f|%2e%2e%2f|/etc/passwd)", re.I)
SCAN_RE = re.compile(r"(sqlmap|nikto|nmap|masscan|acunetix|dirbuster|wpscan|nessus|havij)", re.I)
PROBE_RE = re.compile(r"(/\.env|/\.git|/wp-admin|/wp-login|/phpmyadmin|/xmlrpc\.php|/\.aws)", re.I)


def _short(line: str) -> str:
    line = line.strip()
    return line[:160] + ("..." if len(line) > 160 else "")


def analyze_logs(content: str) -> AnalysisResponse:
    lines = content.splitlines()[:5000]
    fails = Counter()
    accepted = set()
    hits = defaultdict(list)  # category -> sample lines
    counts = Counter()

    for line in lines:
        m = IP_RE.search(line)
        ip = m.group(0) if m else "unknown"
        if FAIL_RE.search(line):
            fails[ip] += 1
        if ACCEPT_RE.search(line):
            accepted.add(ip)
        for name, rx in (("sql_injection", SQLI_RE), ("xss", XSS_RE), ("path_traversal", TRAV_RE),
                         ("scanner", SCAN_RE), ("sensitive_probe", PROBE_RE)):
            if rx.search(line):
                counts[name] += 1
                if len(hits[name]) < 2:
                    hits[name].append(_short(line))

    findings: List[Finding] = []
    for ip, n in fails.most_common(5):
        if n >= 5:
            findings.append(Finding(type="brute_force", severity="Critical" if n >= 10 else "High",
                                    description=f"{n} failed login attempts from {ip}", evidence=f"{ip}: {n} failures"))
            if ip in accepted:
                findings.append(Finding(type="possible_compromise", severity="Critical",
                                        description=f"Successful login from {ip} after {n} failures",
                                        evidence=f"{ip} succeeded after repeated failures"))

    rules = {
        "sql_injection": ("SQL injection patterns in requests", "High", "Critical"),
        "xss": ("Cross-site scripting payloads in requests", "Medium", "High"),
        "path_traversal": ("Path traversal attempts", "High", "High"),
        "scanner": ("Automated security scanner user agents", "Medium", "Medium"),
        "sensitive_probe": ("Probing for sensitive files or admin panels", "Low", "Medium"),
    }
    for name, (desc, low_sev, high_sev) in rules.items():
        n = counts[name]
        if n:
            sev = high_sev if n >= 5 else low_sev
            findings.append(Finding(type=name, severity=sev, description=f"{desc} ({n} lines)",
                                    evidence=" | ".join(hits[name])))

    return finalize("Log", findings, f"No suspicious activity detected in {len(lines)} log lines.")


# ---------------------------------------------------------------- URL
SUSPICIOUS_TLDS = {"zip", "xyz", "top", "tk", "click", "gq", "work", "ml", "cf", "country"}
KEYWORDS = ("login", "verify", "secure", "account", "update", "bank", "wallet", "signin", "confirm")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly"}
BRAND_DOMAINS = {
    "paypal": ["paypal.com"],
    "google": ["google.com", "google.co.in", "googleapis.com"],
    "microsoft": ["microsoft.com", "microsoftonline.com", "live.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk"],
    "facebook": ["facebook.com"],
    "netflix": ["netflix.com"],
    "instagram": ["instagram.com"],
}


def url_findings(raw: str) -> List[Finding]:
    raw = raw.strip()
    url = raw if "://" in raw else "http://" + raw
    out: List[Finding] = []
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
    except ValueError:
        return [Finding(type="suspicious_url", severity="Medium", description="URL could not be parsed", evidence=raw[:120])]
    if not host:
        return [Finding(type="suspicious_url", severity="Medium", description="URL has no host", evidence=raw[:120])]

    try:
        ipaddress.ip_address(host)
        out.append(Finding(type="ip_host", severity="High", description="Link uses a raw IP address instead of a domain", evidence=host))
    except ValueError:
        pass

    if p.scheme != "https":
        out.append(Finding(type="suspicious_url", severity="Low", description="Link does not use HTTPS", evidence=p.scheme))
    if "@" in (p.netloc or ""):
        out.append(Finding(type="suspicious_url", severity="Medium", description="URL contains '@' which can hide the real destination", evidence=p.netloc[:80]))
    if "xn--" in host:
        out.append(Finding(type="suspicious_url", severity="Medium", description="Punycode domain (possible look-alike characters)", evidence=host))
    if host.count(".") >= 4:
        out.append(Finding(type="suspicious_url", severity="Medium", description="Unusually many subdomains", evidence=host))
    if host.split(".")[-1] in SUSPICIOUS_TLDS:
        out.append(Finding(type="suspicious_url", severity="Medium", description="Top-level domain often abused for phishing", evidence=host))
    if host in SHORTENERS:
        out.append(Finding(type="suspicious_url", severity="Low", description="Shortened link hides the final destination", evidence=host))
    if len(url) > 100:
        out.append(Finding(type="suspicious_url", severity="Low", description="Very long URL", evidence=f"{len(url)} characters"))
    if host.count("-") >= 3:
        out.append(Finding(type="suspicious_url", severity="Low", description="Many hyphens in domain", evidence=host))
    hit = [k for k in KEYWORDS if k in host]
    if hit:
        out.append(Finding(type="suspicious_url", severity="Medium", description="Sensitive keywords in domain name", evidence=", ".join(hit)))
    for brand, domains in BRAND_DOMAINS.items():
        if brand in host and not any(host == d or host.endswith("." + d) for d in domains):
            out.append(Finding(type="brand_impersonation", severity="High",
                               description=f"Domain mentions '{brand}' but is not an official {brand} domain", evidence=host))
            break
    return out


def analyze_url(url: str) -> AnalysisResponse:
    return finalize("URL", url_findings(url), "No common phishing indicators found. This is a heuristic check, not a guarantee of safety.")


# ---------------------------------------------------------------- EMAIL
URGENCY = ("urgent", "immediately", "within 24 hours", "account suspended", "verify your account",
           "final notice", "act now", "your account will be closed", "unusual activity")
CRED_RE = re.compile(r"(password|otp|one[- ]time code|credit card|card number|cvv|ssn|bank details)", re.I)
LINK_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)
ATTACH_RE = re.compile(r"\b[\w\- ]+\.(exe|scr|js|vbs|bat|jar|iso|docm|xlsm|lnk)\b", re.I)
FREEMAIL = ("gmail.com", "yahoo.com", "outlook.com", "hotmail.com")


def analyze_email(sender: str, subject: str, body: str) -> AnalysisResponse:
    text = f"{subject or ''}\n{body}".lower()
    findings: List[Finding] = []

    hits = [w for w in URGENCY if w in text]
    if hits:
        findings.append(Finding(type="phishing_language", severity="Medium" if len(hits) < 3 else "High",
                                description="Urgent or threatening language", evidence=", ".join(hits[:4])))
    if CRED_RE.search(text):
        findings.append(Finding(type="phishing_language", severity="High",
                                description="Message asks for sensitive information", evidence=CRED_RE.search(text).group(0)))
    if re.search(r"dear (customer|user|client)", text):
        findings.append(Finding(type="phishing_language", severity="Low", description="Generic greeting instead of your name"))
    m = ATTACH_RE.search(body)
    if m:
        findings.append(Finding(type="dangerous_attachment", severity="High",
                                description="Mentions a potentially dangerous file type", evidence=m.group(0)))

    sender_l = (sender or "").lower()
    for brand in BRAND_DOMAINS:
        if brand in text and any(sender_l.endswith("@" + d) for d in FREEMAIL):
            findings.append(Finding(type="brand_impersonation", severity="High",
                                    description=f"Claims to be {brand} but is sent from a free email provider", evidence=sender))
            break

    links = list(dict.fromkeys(LINK_RE.findall(body)))[:5]
    for link in links:
        for f in url_findings(link):
            if f.severity in ("Medium", "High"):
                findings.append(Finding(type=f.type, severity=f.severity, description=f"Link issue: {f.description}", evidence=link[:120]))

    return finalize("Email", findings, "No common phishing indicators found. Stay cautious with unexpected messages.")


# ---------------------------------------------------------------- PASSWORD
COMMON = {"password", "123456", "12345678", "qwerty", "abc123", "letmein", "admin", "welcome", "iloveyou",
          "password1", "111111", "123123", "dragon", "monkey", "football", "123456789", "qwerty123"}


def _entropy_bits(pw: str) -> float:
    pool = 0
    if re.search(r"[a-z]", pw): pool += 26
    if re.search(r"[A-Z]", pw): pool += 26
    if re.search(r"\d", pw): pool += 10
    if re.search(r"[^A-Za-z0-9]", pw): pool += 32
    return len(pw) * math.log2(pool) if pool else 0.0


async def _breach_count(pw: str) -> Tuple[int, bool]:
    """HIBP k-anonymity: only the first 5 chars of the SHA-1 hash leave this service."""
    digest = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"https://api.pwnedpasswords.com/range/{prefix}", headers={"Add-Padding": "true"})
            r.raise_for_status()
        for line in r.text.splitlines():
            h, _, count = line.partition(":")
            if h.strip() == suffix:
                return int(count.strip() or 0), True
        return 0, True
    except Exception:
        return 0, False


async def analyze_password(pw: str) -> AnalysisResponse:
    findings: List[Finding] = []
    if pw.lower() in COMMON:
        findings.append(Finding(type="common_password", severity="Critical", description="Password is on common password lists"))
    if len(pw) < 8:
        findings.append(Finding(type="weak_password", severity="High", description=f"Too short ({len(pw)} characters)"))
    elif len(pw) < 12:
        findings.append(Finding(type="weak_password", severity="Medium", description="Shorter than the recommended 12+ characters"))
    classes = sum(bool(re.search(p, pw)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if classes < 3 and len(pw) < 16:
        findings.append(Finding(type="weak_password", severity="Medium", description="Uses fewer than 3 character types"))
    if re.search(r"(.)\1{2,}", pw) or re.search(r"(0123|1234|2345|abcd|qwer)", pw.lower()):
        findings.append(Finding(type="weak_password", severity="Medium", description="Contains repeated or sequential characters"))
    bits = _entropy_bits(pw)
    if bits < 40:
        findings.append(Finding(type="weak_password", severity="High", description=f"Low estimated entropy (~{int(bits)} bits)"))
    elif bits < 60:
        findings.append(Finding(type="weak_password", severity="Medium", description=f"Moderate estimated entropy (~{int(bits)} bits)"))

    count, checked = await _breach_count(pw)
    if checked and count > 0:
        findings.append(Finding(type="breached_password", severity="Critical", description=f"Found in known data breaches {count:,} times"))
    elif not checked:
        findings.append(Finding(type="breach_check", severity="Info", description="Breach database unreachable; breach check skipped"))

    tail = "no known breaches found." if checked else "breach check was unavailable, so breaches were not verified."
    return finalize("Password", findings, f"Password looks strong (~{int(bits)} bits of entropy); {tail}")
