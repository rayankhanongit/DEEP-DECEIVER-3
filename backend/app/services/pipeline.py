"""
The DEEP-DECEIVER request pipeline.

    sensors (Fast Filter, stateful window, semantic similarity)   -> evidence
    CrewAI crew: Sentry -> Analyst -> Orchestrator                -> DECISION
    production assistant  |  honeypot  |  hold                    -> reply
    kill chain, MITRE, forensics, security monitor                -> records

The sensors never decide. Routing comes only from the Orchestrator agent's
structured verdict. If the agents cannot produce one, the message is *held*
(a neutral "try again" reply): it is neither forwarded to production nor
treated as an attack, because no decision exists. A session that is already
contained simply stays in the honeypot.
"""

import logging
import threading
import time

from app.agents.sentry import Sentry
from app.crew.runtime import AnalysisUnavailable, DEEPDeceiverCrewRuntime
from app.deception import conversation as honeypot
from app.detection.fast_filter import fast_filter
from app.detection.stateful import StatefulDetector
from app.intelligence.forensic import ForensicLogger
from app.intelligence.kill_chain import KillChainTracker
from app.intelligence.mitre import map_to_mitre_atlas
from app.security.monitor import get_monitor
from app.services import chat_session
from app.services.sessions import containment
from app.utils.bounded import BoundedStore

logger = logging.getLogger("deep_deceiver.pipeline")

UNAVAILABLE_REPLY = (
    "Sorry, I'm having trouble responding right now. "
    "Please try again in a few seconds."
)

INFLUX_RETRY_SECONDS = 30


class Pipeline:

    def __init__(
        self,
        crew=None,
        sensor=None,
        kill_chain=None,
        forensic=None,
        registry=None,
        monitor_factory=None,
    ):
        self.crew = crew or DEEPDeceiverCrewRuntime()
        self._sensor = sensor
        self.kill_chain = kill_chain or KillChainTracker()
        self.forensic = forensic or ForensicLogger()
        self.containment = registry or containment
        self._monitor_factory = monitor_factory or get_monitor

        self.stateful = BoundedStore(max_items=5000, ttl_seconds=6 * 3600)

        self._influx = None
        self._influx_retry_at = 0.0
        self._influx_lock = threading.Lock()

    # --------------------------------------------------
    # Sensors
    # --------------------------------------------------

    @property
    def sensor(self) -> Sentry:
        if self._sensor is None:
            self._sensor = Sentry()

        return self._sensor

    def warm_up(self):
        try:
            self.sensor.analyze("hello")
        except Exception as error:
            logger.warning("Semantic sensor warm-up failed: %s", type(error).__name__)

    def _semantic(self, message: str) -> dict | None:
        try:
            return self.sensor.analyze(message)
        except Exception as error:
            # The agents still judge the message without this evidence.
            logger.warning("Semantic sensor unavailable: %s", type(error).__name__)
            return None

    def _detector(self, session_id: str) -> StatefulDetector:
        detector = self.stateful.get(session_id)

        if detector is None:
            detector = StatefulDetector()
            self.stateful[session_id] = detector

        return detector

    # --------------------------------------------------
    # Agent analysis
    # --------------------------------------------------

    def analyze_only(self, message: str) -> dict:
        """Run the agents on a message without touching any session state
        (operator tool). Raises AnalysisUnavailable."""

        return self.crew.analyze(
            text=message,
            fast_filter_result=fast_filter(message),
            stateful_result=StatefulDetector().analyze(message),
            semantic_result=self._semantic(message),
            recent_turns=[],
            already_contained=False,
        )

    # --------------------------------------------------
    # Main entry point
    # --------------------------------------------------

    def process(
        self,
        message: str,
        session_id: str,
        history: list[dict] | None = None,
        *,
        origin: str = "user",
        system_prompt: str | None = None,
    ) -> dict:
        """
        origin="user"      a real chat message (full forensics and alerting)
        origin="red_team"  an assessment attack: same defence, but the Red Team
                           service records its own findings
        """

        chat_session.seed_history(session_id, history)

        t_start = time.perf_counter()

        # ---- 1. sensors ------------------------------------------------
        filter_result = fast_filter(message)

        detector = self._detector(session_id)
        stateful_result = detector.analyze(message)
        recent_turns = detector.recent(4)
        detector.add_message(message)

        semantic = self._semantic(message)

        was_contained = self.containment.is_contained(session_id)

        t_sensors = time.perf_counter()

        # ---- 2. the agents decide ---------------------------------------
        verdict = None
        engine = "crewai"
        unavailable = None

        try:
            verdict = self.crew.analyze(
                text=message,
                fast_filter_result=filter_result,
                stateful_result=stateful_result,
                semantic_result=semantic,
                recent_turns=recent_turns,
                already_contained=was_contained,
            )
        except AnalysisUnavailable as error:
            engine = "unavailable"
            unavailable = {"reason": error.reason, "retry_after": error.retry_after}
        except Exception as error:
            logger.warning("Security analysis failed: %s", type(error).__name__)
            engine = "unavailable"

        t_agents = time.perf_counter()

        # ---- 3. containment state --------------------------------------
        if verdict is not None:
            hostile = verdict["orchestrator"]["route"] == "shadow"

            if was_contained:
                contained = self.containment.record_verdict(session_id, hostile)
            elif hostile:
                self.containment.contain(session_id, "agent_verdict")
                contained = True
            else:
                contained = False
        else:
            contained = was_contained

        # ---- 4. reply ---------------------------------------------------
        decoy = None

        if contained:
            # No banner, no wording that reveals the deception: the sender
            # keeps talking to the same "Atlas", now backed by fictional data.
            persona = honeypot.persona_for(session_id)

            response = honeypot.reply(
                session_id=session_id,
                message=message,
                persona=persona,
                prior_history=chat_session.get_history(session_id),
            )

            response_source = "decoy"
            status = "contained"
            environment = "shadow"

            decoy = {
                "agent": "decoy",
                "persona": persona,
                "environment": "shadow",
                "response_type": "honeypot_conversation",
                "response": response,
                "interaction_count": honeypot.turn_count(session_id),
                "production_access": False,
            }

        elif verdict is None:
            # No agent decision: neither forward nor accuse.
            response = UNAVAILABLE_REPLY
            response_source = "unavailable"
            status = "active"
            environment = "held"

        else:
            try:
                response = chat_session.production_reply(
                    session_id, message, system_prompt=system_prompt
                )
            except Exception:
                response = UNAVAILABLE_REPLY

            response_source = "production"
            status = "active"
            environment = "production"

        t_reply = time.perf_counter()

        # ---- 5. detection summary --------------------------------------
        detection = self._detection(filter_result, stateful_result, verdict, engine, unavailable)

        analyst = detection["analyst"]

        stage = analyst.get("kill_chain_stage")
        stage = None if stage in (None, "none") else stage

        if verdict is not None and origin == "user":
            kill_chain = self.kill_chain.update(
                session_id=session_id,
                message=message,
                attack_category=analyst["attack_category"],
                attacker_goal=analyst["attacker_goal"],
                stage=stage,
            )
        else:
            kill_chain = {
                "session_id": session_id,
                "current_stage": None,
                "completed_stages": [],
                "interaction_count": 0,
                "attack_progression": 0.0,
            }

        mitre = map_to_mitre_atlas(analyst["attack_category"])

        detection["kill_chain"] = kill_chain
        detection["mitre"] = mitre

        guard = self._guard(filter_result, semantic, verdict)

        if guard:
            detection["guard"] = guard

        result = {
            "security": None,
            "response": response,
            "response_source": response_source,
            "detection": detection,
            "kill_chain": kill_chain,
            "mitre": mitre,
            "decoy": decoy,
            "timings_ms": {
                "sensors": round((t_sensors - t_start) * 1000),
                "agents": round((t_agents - t_sensors) * 1000),
                "reply": round((t_reply - t_agents) * 1000),
                "total": round((t_reply - t_start) * 1000),
            },
            "forensic_event": None,
            "session": {
                "session_id": session_id,
                "status": status,
                "environment": environment,
                "production_access": environment == "production",
            },
        }

        if origin != "user":
            return result

        # ---- 6. forensics and monitoring (real users only) --------------
        forensic_event = self.forensic.create_event(
            message=message,
            detection=detection,
            response_source=response_source,
            session_id=session_id,
        )

        self._store(forensic_event)

        result["forensic_event"] = forensic_event

        if verdict is not None or contained:
            result["security"] = self._monitor_factory().process_chat(
                message=message,
                response=response,
                session_id=session_id,
                routed_to_shadow=contained,
                sentry_result=detection["sentry"],
                analyst_result=analyst,
                orchestrator_result=detection["orchestrator"],
                system_prompt=system_prompt or _production_prompt(),
            )
        else:
            result["security"] = {
                "level": "UNKNOWN",
                "is_attack": False,
                "risk_score": 0,
                "outcome": "UNKNOWN",
                "alert_triggered": False,
                "event_id": None,
            }

        return result

    # --------------------------------------------------
    # Helpers
    # --------------------------------------------------

    @staticmethod
    def _detection(filter_result, stateful_result, verdict, engine, unavailable=None) -> dict:
        if verdict is None:
            sentry = {"flagged": False, "score": 0.0, "threshold": 0.0, "rationale": ""}
            analyst = {
                "intent": "unknown",
                "attack_category": "unknown",
                "attacker_goal": "unknown",
                "risk_score": 0.0,
                "multi_turn": False,
                "kill_chain_stage": "none",
                "rationale": "",
            }
            orchestrator = {
                "route": "hold",
                "action": "hold",
                "final_risk_score": 0.0,
                "threshold": 0.0,
                "decision_reason": "analysis_unavailable",
                "rationale": "",
            }
        else:
            sentry = {k: v for k, v in verdict["sentry"].items() if k != "obfuscation"}
            analyst = dict(verdict["analyst"])
            orchestrator = dict(verdict["orchestrator"])

        return {
            "fast_filter": {
                "flagged": filter_result["flagged"],
                "score": filter_result["score"],
                "matched_patterns": filter_result["matched_patterns"],
            },
            "stateful": {
                "detected": stateful_result["detected"],
                "score": stateful_result["score"],
                "signals": stateful_result["signals"],
                "history_length": stateful_result["history_length"],
            },
            "sentry": sentry,
            "analyst": analyst,
            "orchestrator": orchestrator,
            "analysis_engine": engine,
            "agents_model": (verdict or {}).get("model"),
            "token_usage": (verdict or {}).get("usage"),
            "unavailable": unavailable,
        }

    @staticmethod
    def _guard(filter_result, semantic, verdict) -> dict | None:
        """Visibility only, never an override: report when the agents let
        through a message that both sensors considered an attack, so the
        operator can review the agents' judgement."""

        if verdict is None or verdict["orchestrator"]["route"] != "production":
            return None

        if not (filter_result["flagged"] and (semantic or {}).get("flagged")):
            return None

        logger.warning(
            "Agents routed to production a message both sensors flagged (intent=%s)",
            verdict["analyst"]["intent"],
        )

        return {
            "evidence_conflict": True,
            "note": "Both sensors flagged this message; the agents allowed it. Review recommended.",
        }

    # --------------------------------------------------

    def _get_influx(self):
        with self._influx_lock:
            if self._influx is None and time.time() >= self._influx_retry_at:
                try:
                    from app.database.influx import InfluxDBService

                    self._influx = InfluxDBService()
                except Exception as error:
                    logger.warning("Forensic store unavailable: %s", type(error).__name__)
                    self._influx_retry_at = time.time() + INFLUX_RETRY_SECONDS

            return self._influx

    def _store(self, event: dict):
        influx = self._get_influx()

        if influx is None:
            return

        try:
            influx.write_event(event)
        except Exception as error:
            logger.warning("Forensic event not stored: %s", type(error).__name__)
            self._influx_retry_at = time.time() + INFLUX_RETRY_SECONDS
            self._influx = None

    # --------------------------------------------------

    def forget(self, session_id: str):
        """Drop every piece of server-side state for a session."""

        self.stateful.pop(session_id, None)
        self.containment.release(session_id)
        self.kill_chain.sessions.pop(session_id, None)
        chat_session.reset(session_id)
        honeypot.reset(session_id)


def _production_prompt() -> str:
    from app.services.llm import SYSTEM_PROMPT

    return SYSTEM_PROMPT


pipeline = Pipeline()
