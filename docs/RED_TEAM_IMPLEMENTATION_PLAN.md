# Red Team & Security Monitoring — Implementation Plan

This document records what was found in the repository *before* the
Red Team / jailbreak-monitoring work, and exactly how the new components
were integrated. Nothing here is assumed from the repository name; every
item below was read from the source.

## 1. Current application architecture

| Layer | Technology |
|---|---|
| Frontend | React 19 + Vite (`frontend/`), plain CSS, no router, no UI library |
| Backend | FastAPI (`backend/app/main.py`), CORS for `localhost:5173` |
| LLM provider | Groq, model `openai/gpt-oss-20b`, via the `groq` SDK (`app/services/llm.py`) and CrewAI's `LLM` (`app/crew/llm.py`) |
| Agents | CrewAI crew: Sentry, Analyst, Orchestrator, Decoy (`app/crew/`, `app/agents/`) |
| Storage | InfluxDB 2.7 in Docker (`docker/docker-compose.yml`), wrapper `app/database/influx.py` |
| Tests | pytest in `backend/tests/` (+ offline evaluation scripts in `validation/`) |

## 2. Current frontend flow

`App.jsx` held a header with two tabs (LLM Interface / SOC Dashboard) and
the chat history. `ChatPage.jsx` POSTs to `/chat` and renders the model
reply plus a detection panel; `SOCPage.jsx` reads `/soc/stats` and
`/soc/events`.

## 3. Current backend flow (`POST /chat`, `app/api/chat.py`)

1. `fast_filter` — regex + obfuscation + indirect-injection patterns
2. `StatefulDetector` — multi-turn escalation per session
3. CrewAI analysis (`DEEPDeceiverCrewRuntime.analyze`) → Sentry score,
   Analyst intent/category/risk, Orchestrator route
4. Kill-chain tracker and MITRE ATLAS mapping
5. Route: `production` → `generate_response()`; `shadow` → decoy agent
6. Forensic event → InfluxDB (`forensic_events` measurement)
7. JSON response with detection details

## 4. LLM / model flow

One Groq client in `app/services/llm.py` (production answers) and one
CrewAI LLM in `app/crew/llm.py` (security agents). The system prompt was
an inline string inside `generate_response`.

## 5–6. Existing validation and security pipeline

Fast Filter → Stateful → Sentry (embedding similarity) → Analyst →
Orchestrator threshold 0.85 → shadow routing. Offline validation scripts
in `validation/` (adversarial, indirect, stateful, giskard).

## 7. Storage

InfluxDB bucket (`INFLUXDB_*` env vars). Measurement `forensic_events`.

## 8. Docker architecture

`docker-compose.yml` runs **only InfluxDB**. The backend and frontend run
on the host (`commands.txt`). This matters for host notifications — see §14.

## 9. Testing architecture

`backend/tests/test_*.py`, run from `backend/`. Some tests call Groq and
InfluxDB for real.

## 10. Files modified

| File | Change |
|---|---|
| `backend/app/api/chat.py` | After routing, call `get_monitor().process_chat(...)`; add `security` object to the response (never raises) |
| `backend/app/services/llm.py` | Extract `SYSTEM_PROMPT`; add `generate_chat` (multi-turn) and `judge_text` on the **same** client |
| `backend/app/database/influx.py` | Add `write_security_event` / `query_security_events` (new measurement in the **same** bucket) |
| `backend/app/main.py` | Include the two new routers; lifespan hook that closes SSE streams |
| `frontend/src/App.jsx` | Sidebar shell, Red Team modal, alert toast, SSE hook |
| `frontend/src/pages/ChatPage.jsx` | Claude-style chat UI, Red Team button, security badge; detection panel kept (collapsible) |
| `.env.example`, `commands.txt` | New settings and run instructions |

## 11. Files created

* `backend/app/security/` — `config`, `models`, `redaction`, `risk_engine`,
  `detector`, `evaluator`, `event_store`, `notifications`, `alerts`, `monitor`
* `backend/app/red_team/` — `agent`, `service`, `strategies/*`
* `backend/app/api/security.py`, `backend/app/api/red_team.py`
* `backend/tests/test_security_*.py`, `test_red_team.py`, helpers
* `frontend/src/` — `api.js`, `ui.css`, `hooks/useSecurityStream.js`,
  `components/{RedTeamPanel,SecurityToast,Markdown,DetectionDetails}.jsx`,
  `pages/SecurityPage.jsx`
* `scripts/host_alert_listener.py` — optional Docker→host bridge
* `docs/*`, root `README.md`

## 12. How the Red Team agent integrates

`AssessmentService` runs `RedTeamAgent` on a background thread. The agent
talks to the *application's own model* through `generate_chat` (same Groq
client). Findings are scored by `ResponseEvaluator` + `RiskEngine` and
recorded through `SecurityMonitor.record` — the same path chat events use,
so dashboard, logs, store and alerts are shared.

## 13. How jailbreak detection integrates

`JailbreakDetector` does not add a model. It fuses the existing Fast
Filter, Stateful, Sentry and Analyst outputs (already computed in
`chat()`), classifies the attack category, and asks the `RiskEngine` for a
0–100 score. After the reply is produced `ResponseEvaluator` decides
BLOCKED / SUSPICIOUS / SUCCESS so *attempt* and *success* are tracked
separately. A request routed to the shadow environment is BLOCKED by
definition.

## 14. How host notifications integrate

`notification_service.send_security_alert(event)` fans out to providers
(`Console`, `Desktop`, optional `Webhook`). Because the backend runs on the
host, `DesktopNotificationProvider` can show a native Windows notification
directly (PowerShell `NotifyIcon`, no new dependency; macOS `osascript`,
Linux `notify-send`). If the backend is ever containerised, set
`SECURITY_WEBHOOK_URL` and run `scripts/host_alert_listener.py` on the host.
Failures are logged and swallowed. Alerts carry only severity, score,
category and time — never prompt text.

## Decisions on architectural problems met along the way

* **CrewAI/Giskard Python constraint** — the pinned requirements need
  Python 3.12 or 3.13; documented in `commands.txt`.
* **Reasoning model truncation** — `gpt-oss` spends `max_tokens` on hidden
  reasoning, producing empty answers; the Red Team target uses a larger
  budget and `reasoning_effort="low"`.
* **Hot reload blocked by SSE** — open event streams prevented graceful
  shutdown; streams now end on shutdown / client disconnect.
