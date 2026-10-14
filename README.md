# DEEP-DECEIVER

Agentic active-defence framework that protects an LLM against prompt
injection and jailbreaks. Three **CrewAI agents** (Sentry → Analyst →
Orchestrator) judge every message and decide whether it reaches the
production assistant or a honeypot; cheap sensors (Fast Filter, stateful
window, semantic similarity) only supply them with evidence. Forensic logging
in InfluxDB and a SOC dashboard.

## How a message is handled

```
message ──► sensors (evidence only) ──► CrewAI crew ──► route
            Fast Filter                 Sentry agent      production assistant
            Stateful window             Analyst agent     honeypot ("Atlas", fake data)
            Semantic similarity         Orchestrator      hold (agents unavailable)
```

* **The agents' structured verdicts are the only security decision.** A
  sensor can never route a message by itself; if both sensors flag a message
  the agents allowed, the operator view marks it `guard.evidence_conflict`
  for review, nothing is overridden.
* **If the agents cannot answer** (rate limit, malformed output, no key) the
  message is *held*: the user gets a neutral "try again" reply, the message is
  not forwarded to the model and not treated as an attack. A session that is
  already contained simply stays in the honeypot. There is no rule-based
  fallback decision.
* **One identity.** Production and honeypot are both "Atlas" (Northwind IT
  assistant), the honeypot inherits the conversation so far, and the
  production prompt never mentions the defence.
* **Containment is sticky but not permanent** (`CONTAINMENT_TTL_SECONDS`,
  `CONTAINMENT_CLEAN_TURNS`, operator release).
* **Session ids are issued and signed by the server** (`SESSION_SECRET`);
  clients cannot choose, share or forge them.
* **Red Team assessments attack this whole pipeline**, not the bare model, and
  report a containment rate next to model robustness.
* Prompts are untrusted data for the agents themselves: they are passed in a
  delimited block with instructions to treat them as data, and agent outputs
  are schema-validated. This reduces, but cannot eliminate, the risk of an
  attacker steering the agents; watch `guard.evidence_conflict` events.

## Run it

Requires Docker Desktop, Node 20+, **Python 3.12 or 3.13** and a Groq API key.

```bash
cp .env.example .env            # then put your GROQ_API_KEY in it

# Terminal 1 – InfluxDB
docker compose --env-file .env -f docker/docker-compose.yml up -d

# Terminal 2 – backend
cd backend
py -3.12 -m venv proj && proj\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload

# Terminal 3 – frontend
cd frontend
npm install
npm run dev                      # http://localhost:5173
```

Tests: `cd backend && pytest tests` (offline: a local fake model server
drives the real CrewAI crew; no Groq or InfluxDB needed except `test_soc.py` and
`test_influx.py`, which talk to a running InfluxDB).

Rate limits and latency: the agents try the models in `CREW_MODELS` in order and
switch on a Groq 429 (each model has its own quota); a local token budget
(`CREW_TPM_LIMIT`) queues or quickly holds messages instead of hanging, and CrewAI's
own retries are disabled so one throttled message cannot trigger dozens of calls.
Sentry and Analyst run concurrently, then the Orchestrator. The operator view shows
`timings_ms`, `agents_model` and `token_usage` for every message. Sub-100 ms
detection is only possible for the local sensors; LLM agents take seconds.

OWASP validation (risks a prompt-injection gateway can address: LLM01 Prompt
Injection, LLM02 Sensitive Information Disclosure, LLM07 System Prompt Leakage):
`python validation/giskard_owasp.py --split heldout --pace --resume` replays the
held-out corpus (106 attacks, 66 benign, plus multi-turn escalations) as Giskard
scenarios against the real pipeline and reports detection per OWASP risk with 95%
Wilson intervals; the 95% target counts as met only if the *lower* bound is >= 95%
(zero misses needs at least 73 attacks, two misses 142). On the Groq free tier the
run takes several days of quota; it checkpoints and resumes. Add an independent
public benchmark with `fetch_external.py` + `--external`.

Detection quality: `cd validation && python evaluate.py --mode filter|sensors|agents`
reports recall / false-positive rate with confidence intervals on a
development / held-out split, including 60 hard benign prompts.
`python leakage_check.py` flags validation attacks that duplicate the
Sentry's reference prompts.

---

## Stealth honeypot and operator view

When the defence decides a session is hostile, the attacker is **not told**.
Their chat looks exactly like a normal assistant: no alerts, badges or
"protected environment" text. Behind the scenes the session is moved to the
shadow environment and the persona "Atlas" keeps the conversation going with
realistic, entirely fictional data (`backend/app/deception/dataset.py`),
consistent for the whole session. Replies are never refusals, and harmful
requests (malware, weapons ...) are deflected in character.

* `POST /chat` returns **only** `{response, session}` to ordinary clients.
* Everything else (detection details, events, alerts, Red Team, SOC) needs the
  `OPERATOR_TOKEN` from `.env`, sent as `X-Operator-Token`.
* In the browser press **Ctrl+Shift+O** (no visible button), paste the token,
  and the Security Monitor, SOC dashboard, Red Team button and live alerts
  appear. Ctrl+Shift+O again (or *Lock operator view*) hides them.
* The operator follows the attacker live in *Security Monitor → 🍯 Honeypot*,
  and gets a host desktop notification for high-risk events.

# Adaptive Red Team Agent

## What it does

* **⚔ Red Team button** in the chat opens an assessment panel. The agent
  attacks *this application's own model* with controlled adversarial
  prompts, evaluates every reply and produces a report (tests executed,
  blocked / suspicious / successful, overall risk, model robustness,
  expandable findings).
* **Jailbreak monitor** runs on every normal chat message, scores it,
  evaluates the reply and raises alerts on the host computer.
* **Security Monitor** page shows live metrics and events.

## Why it exists

To tell *unusual* requests from *active bypass attempts*, to measure how
robust the model really is, and to alert the operator in real time.

## How it works

```
User
 ↓
Jailbreak Detector      (scores the CrewAI agents' verdicts; no rules of its own)
 ↓
Risk Engine             (0–100 → SAFE/LOW/MEDIUM/HIGH/CRITICAL)
 ↓
Target LLM  (or shadow environment)
 ↓
Response Evaluator      (marker, canary, system-prompt overlap, refusal, optional LLM judge)
 ↓
Security Event          (structured log + InfluxDB `security_events`)
 ↓
Alert Engine            (threshold + cool-down)
 ↓
Host Notification       (+ live toast in the browser via SSE)
```

### Attack *attempt* vs *successful jailbreak*

| Outcome | Meaning |
|---|---|
| `BLOCKED` | attack detected, the model/defence resisted ("ATTACK BLOCKED") |
| `SUSPICIOUS` | attack detected, model behaviour was questionable |
| `SUCCESS` | attack detected **and** the model violated a boundary ("JAILBREAK SUCCESS") |

They are stored, counted and displayed separately (dashboard, logs,
metrics, Red Team results, alerts). *Model robustness* =
blocked ÷ (blocked + suspicious + successful).

## Attack categories

Instruction Override · Prompt Boundary/Disclosure · Role Manipulation ·
Context Manipulation · Indirect Prompt Injection · Multi-turn
Manipulation · Safety Boundary Testing — each with three escalation
levels (`backend/app/red_team/strategies/`, add a class to extend).

Tests are harmless by construction: "success" means emitting a random
marker, leaking a random sandbox canary token, or dropping the persona.

## Modes

| Mode | Tests |
|---|---|
| Quick Scan | 3 (`RED_TEAM_QUICK_TESTS`) |
| Standard | 7 (`RED_TEAM_STANDARD_TESTS`) |
| Deep | 10 (`RED_TEAM_DEEP_TESTS`) |

The agent is adaptive (resisted → new category, weakness → follow-up at
a higher level) and bounded by `RED_TEAM_MAX_TESTS`, `RED_TEAM_MAX_TURNS`,
`RED_TEAM_TIMEOUT` and a Stop button. It can only reach the app's own model.

## Risk scoring

`45·confidence + 25·category weight + outcome (10/20/30) + repeats (+4,
max 12) + multi-turn (+8) + exposure (+10)`, clamped to 0–100; blocked Red
Team findings are scaled to 40 %. See `docs/RED_TEAM_ARCHITECTURE.md`.

## Host alerts

At `risk ≥ SECURITY_ALERT_THRESHOLD` (default 70) a native desktop
notification shows severity, score, category and time — never the prompt.
Windows uses a PowerShell balloon (no extra dependency). Provider
abstraction: Desktop, Console, Webhook. Test it from *Security Monitor →
Send test host alert* or `POST /security/alerts/test`.

### Docker consideration

`docker-compose.yml` runs only InfluxDB; the backend runs on the host, so
it can notify directly. If you containerise the backend, a container cannot
show host UI: set `SECURITY_WEBHOOK_URL=http://host.docker.internal:8765/alert`
and run `python scripts/host_alert_listener.py` on the host.

## Configuration

See `.env.example`: `RED_TEAM_*`, `SECURITY_ALERT_THRESHOLD`,
`CRITICAL_ALERT_THRESHOLD`, `SECURITY_ALERT_COOLDOWN`,
`DESKTOP_NOTIFICATIONS`, `SECURITY_LOG_LEVEL`, `SECURITY_WEBHOOK_URL`.

## API

| Endpoint | Purpose |
|---|---|
| `GET /red-team/config` | modes, categories, limits |
| `POST /red-team/start` | `{mode, categories}` → `assessment_id` |
| `GET /red-team/{id}` | live progress + findings |
| `GET /red-team/{id}/results` | final report (409 while running) |
| `POST /red-team/{id}/stop` | stop early |
| `POST /security/analyze` | classify a message (read-only) |
| `GET /security/events` | stored events (`limit`, `min_severity`, `source`) |
| `GET /security/stats` | dashboard metrics |
| `GET /security/stream` | Server-Sent Events for live alerts |
| `POST /security/alerts/test` | fire a test host alert |

## Testing

`backend/tests/test_security_*.py` and `test_red_team.py` cover detection,
risk, evaluation, alert thresholds, desktop notification, persistence,
redaction, assessments, limits/timeouts, API validation and dashboard
statistics, all with mocked models.

More detail: `docs/RED_TEAM_ARCHITECTURE.md`,
`docs/RED_TEAM_IMPLEMENTATION_PLAN.md`.
