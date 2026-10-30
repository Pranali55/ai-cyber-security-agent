# 🛡️ AI Cyber Security Agent

A **defensive** security analysis service built with **.NET 8**, **Python FastAPI**, **SQL Server** and optional **OpenAI GPT-4o-mini**. Paste in logs, links, emails or passwords and get a risk score, findings and remediation steps, like a mini SOC assistant.

## ✨ What it analyzes

| Scanner | Detects |
|---------|---------|
| 📜 **Logs** | Brute-force logins, success-after-failures (possible compromise), SQL injection, XSS, path traversal, scanner tools (sqlmap, nikto...), probing for `.env` / `.git` / admin panels |
| 🔗 **URLs** | Raw-IP links, brand impersonation, punycode look-alikes, suspicious TLDs, keyword-stuffed domains, link shorteners |
| ✉️ **Emails** | Urgent/threatening language, credential requests, dangerous attachments, free-mail brand spoofing, risky links inside the body |
| 🔑 **Passwords** | Length, entropy, common-password lists, patterns, and known data breaches via Have I Been Pwned (k-anonymity: only 5 hash characters leave the service) |

Every scan returns a **severity** (Info → Critical), a **0-100 risk score**, **findings** and **recommendations**. Reports are saved per user, with a dashboard.

## 🔒 Privacy by design
- Passwords are analyzed but **never stored** (reports save `[redacted]`).
- The optional LLM only receives finding *types and descriptions*, never raw logs, evidence or passwords.
- Works **without an OpenAI key**: detection is rule-based; the LLM only polishes the summary.

## 🏗️ Tech stack
.NET 8 (ASP.NET Core, EF Core, JWT) · Python 3.11 + FastAPI · SQL Server 2022 · OpenAI (optional) · Docker Compose

## 🚀 Run it
```bash
copy .env.example .env      # optional: add OPENAI_API_KEY
docker-compose up --build
```
- API + Swagger: http://localhost:5000/swagger
- Agent docs: http://localhost:8000/docs

## 📡 Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` · `/api/auth/login` | Account + JWT |
| POST | `/api/security/scan-logs` | `{ "content": "..." }` |
| POST | `/api/security/scan-url` | `{ "url": "..." }` |
| POST | `/api/security/scan-email` | `{ "sender", "subject", "body" }` |
| POST | `/api/security/scan-password` | `{ "password": "..." }` |
| GET | `/api/security/dashboard` | Totals, risk by severity/type |
| GET | `/api/security/reports` · `/reports/{id}` | History |
| DELETE | `/api/security/reports/{id}` | Delete a report |

## 🧪 Try it
Scan this log sample with `scan-logs`:
```
Oct 30 10:01:01 sshd[812]: Failed password for root from 203.0.113.9 port 22
(repeat 10x)
Oct 30 10:01:20 sshd[812]: Accepted password for root from 203.0.113.9 port 22
198.51.100.7 - - "GET /items?id=1 UNION SELECT user,pass FROM users" 200 "sqlmap/1.7"
```
Expected: **Critical**, with brute force, possible compromise, SQL injection and scanner findings.

## ⚠️ Note
URL and email checks are heuristics, not a replacement for a full email gateway or threat-intelligence feed. This tool is for **defending your own systems and data**.

## 📁 Structure
```
ai-cyber-security-agent/
├── backend-dotnet/   # API, auth, history, dashboard
├── python-agent/     # detectors.py (rules) + enrich.py (optional LLM)
└── docker-compose.yml
```
