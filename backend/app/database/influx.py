import json
import os

from dotenv import load_dotenv
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS


load_dotenv()


INFLUXDB_URL = os.getenv("INFLUXDB_URL")
INFLUXDB_TOKEN = os.getenv("INFLUXDB_TOKEN")
INFLUXDB_ORG = os.getenv("INFLUXDB_ORG")
INFLUXDB_BUCKET = os.getenv("INFLUXDB_BUCKET")


import re

_RELATIVE_RANGE = re.compile(r"^-\d{1,4}(s|m|h|d|w|mo|y)$")
_ABSOLUTE_RANGE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def validate_time_range(value: str) -> str:
    """Flux `range(start: ...)` accepts expressions, so only a relative
    duration like -24h or an RFC3339 timestamp is allowed through."""

    if not isinstance(value, str) or not (
        _RELATIVE_RANGE.match(value) or _ABSOLUTE_RANGE.match(value)
    ):
        raise ValueError("time_range must look like -24h, -7d or 2026-01-01T00:00:00Z")

    return value


def _safe_limit(limit) -> int:
    return max(1, min(int(limit), 5000))


class InfluxDBService:
    """
    Handles writing and querying forensic events
    stored in InfluxDB.
    """

    def __init__(self):
        if not all([
            INFLUXDB_URL,
            INFLUXDB_TOKEN,
            INFLUXDB_ORG,
            INFLUXDB_BUCKET
        ]):
            raise RuntimeError(
                "InfluxDB configuration is incomplete."
            )

        self.client = InfluxDBClient(
            url=INFLUXDB_URL,
            token=INFLUXDB_TOKEN,
            org=INFLUXDB_ORG
        )

        self.write_api = self.client.write_api(
            write_options=SYNCHRONOUS
        )

        self.query_api = self.client.query_api()

    # --------------------------------------------------
    # WRITE
    # --------------------------------------------------

    def write_event(self, event: dict):
        """
        Store a forensic event in InfluxDB.
        """

        detection = event["detection"]
        analysis = event["analysis"]
        orchestration = event["orchestration"]

        kill_chain = event.get(
            "kill_chain",
            {}
        )

        mitre = event.get(
            "mitre",
            {}
        )

        current_stage = kill_chain.get(
            "current_stage"
        )

        mitre_id = mitre.get(
            "id"
        )

        mitre_tactic = mitre.get(
            "tactic"
        )

        mitre_technique = mitre.get(
            "technique"
        )

        point = (
            Point("forensic_events")

            # ------------------------------
            # Tags
            # ------------------------------

            .tag(
                "session_id",
                event["session_id"]
            )

            .tag(
                "response_source",
                event["response_source"]
            )

            .tag(
                "attack_category",
                analysis["attack_category"]
            )

            .tag(
                "intent",
                analysis["intent"]
            )

            # Kill Chain tag
            .tag(
                "kill_chain_stage",
                current_stage or "unknown"
            )

            # MITRE tags
            .tag(
                "mitre_id",
                mitre_id or "unknown"
            )

            .tag(
                "mitre_technique",
                mitre_technique or "unknown"
            )

            # ------------------------------
            # Fields
            # ------------------------------

            .field(
                "message",
                event["input"]["message"]
            )

            .field(
                "fast_filter_score",
                detection["fast_filter_score"]
            )

            .field(
                "sentry_score",
                detection["sentry_score"]
            )

            .field(
                "sentry_flagged",
                detection["sentry_flagged"]
            )

            .field(
                "risk_score",
                analysis["risk_score"]
            )

            .field(
                "final_risk_score",
                orchestration["final_risk_score"]
            )

            .field(
                "route",
                orchestration["route"]
            )

            .field(
                "action",
                orchestration["action"]
            )

            # Kill Chain progression
            .field(
                "kill_chain_progression",
                kill_chain.get(
                    "attack_progression",
                    0.0
                )
            )

            .field(
                "kill_chain_interaction_count",
                kill_chain.get(
                    "interaction_count",
                    0
                )
            )

            # MITRE tactic
            .field(
                "mitre_tactic",
                mitre_tactic or "unknown"
            )
        )

        self.write_api.write(
            bucket=INFLUXDB_BUCKET,
            org=INFLUXDB_ORG,
            record=point
        )

    # --------------------------------------------------
    # READ
    # --------------------------------------------------

    def query_events(
        self,
        time_range: str = "-24h",
        limit: int = 100
    ) -> list[dict]:
        """
        Retrieve forensic events from InfluxDB.

        Parameters:
            time_range:
                Flux time range such as "-1h", "-24h", "-7d".

            limit:
                Maximum number of events to return.
        """

        time_range = validate_time_range(time_range)
        limit = _safe_limit(limit)

        query = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
            |> range(start: {time_range})
            |> filter(fn: (r) =>
                r._measurement == "forensic_events"
            )
            |> pivot(
                rowKey: ["_time"],
                columnKey: ["_field"],
                valueColumn: "_value"
            )
            |> sort(
                columns: ["_time"],
                desc: true
            )
            |> limit(n: {limit})
        '''

        tables = self.query_api.query(
            query=query,
            org=INFLUXDB_ORG
        )

        events = []

        for table in tables:
            for record in table.records:

                values = record.values

                event = {
                    "timestamp": (
                        record.get_time().isoformat()
                        if record.get_time()
                        else None
                    ),

                    "session_id": values.get(
                        "session_id"
                    ),

                    "response_source": values.get(
                        "response_source"
                    ),

                    "attack_category": values.get(
                        "attack_category"
                    ),

                    "intent": values.get(
                        "intent"
                    ),

                    "message": values.get(
                        "message"
                    ),

                    "fast_filter_score": values.get(
                        "fast_filter_score"
                    ),

                    "sentry_score": values.get(
                        "sentry_score"
                    ),

                    "sentry_flagged": values.get(
                        "sentry_flagged"
                    ),

                    "risk_score": values.get(
                        "risk_score"
                    ),

                    "final_risk_score": values.get(
                        "final_risk_score"
                    ),

                    "route": values.get(
                        "route"
                    ),

                    "action": values.get(
                        "action"
                    ),

                    # Kill Chain
                    "kill_chain_stage": values.get(
                        "kill_chain_stage"
                    ),

                    "kill_chain_progression": values.get(
                        "kill_chain_progression"
                    ),

                    "kill_chain_interaction_count": values.get(
                        "kill_chain_interaction_count"
                    ),

                    # MITRE ATLAS
                    "mitre_id": values.get(
                        "mitre_id"
                    ),

                    "mitre_tactic": values.get(
                        "mitre_tactic"
                    ),

                    "mitre_technique": values.get(
                        "mitre_technique"
                    )
                }

                events.append(event)

        return events

    # --------------------------------------------------
    # SECURITY EVENTS (jailbreak monitoring / Red Team)
    # --------------------------------------------------

    def write_security_event(self, event: dict):
        """
        Store a structured security event. Only redacted, truncated
        excerpts are ever present in `event` (see app.security.redaction).
        """

        point = (
            Point("security_events")

            .tag("severity", event["severity"])
            .tag("category", event["category"])
            .tag("outcome", event["outcome"])
            .tag("source", event["source"])

            .field("event_id", event["event_id"])
            .field("event_type", event["event_type"])
            .field("risk_score", int(event["risk_score"]))
            .field("confidence", float(event["confidence"]))
            .field("summary", event["summary"])
            .field("session_id", event.get("session_id") or "")
            .field("assessment_id", event.get("assessment_id") or "")
            .field("model_resisted", int(
                -1 if event.get("model_resisted") is None
                else bool(event["model_resisted"])
            ))
            .field("jailbreak_success", bool(event["jailbreak_success"]))
            .field("alert_triggered", bool(event["alert_triggered"]))
            .field("details", json.dumps(event.get("details", {})))
            .field("event_time", event["timestamp"])
        )

        self.write_api.write(
            bucket=INFLUXDB_BUCKET,
            org=INFLUXDB_ORG,
            record=point
        )

    def query_security_events(
        self,
        time_range: str = "-7d",
        limit: int = 1000
    ) -> list[dict]:
        """
        Retrieve stored security events, newest first.
        """

        time_range = validate_time_range(time_range)
        limit = _safe_limit(limit)

        query = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
            |> range(start: {time_range})
            |> filter(fn: (r) =>
                r._measurement == "security_events"
            )
            |> pivot(
                rowKey: ["_time"],
                columnKey: ["_field"],
                valueColumn: "_value"
            )
            |> sort(
                columns: ["_time"],
                desc: true
            )
            |> limit(n: {limit})
        '''

        tables = self.query_api.query(
            query=query,
            org=INFLUXDB_ORG
        )

        events = []

        for table in tables:
            for record in table.records:

                values = record.values

                resisted = values.get("model_resisted")

                try:
                    details = json.loads(values.get("details") or "{}")
                except (TypeError, ValueError):
                    details = {}

                events.append({
                    "event_id": values.get("event_id"),
                    "timestamp": (
                        values.get("event_time")
                        or record.get_time().isoformat()
                    ),
                    "event_type": values.get("event_type"),
                    "severity": values.get("severity"),
                    "category": values.get("category"),
                    "outcome": values.get("outcome"),
                    "source": values.get("source"),
                    "risk_score": int(values.get("risk_score") or 0),
                    "confidence": float(values.get("confidence") or 0.0),
                    "summary": values.get("summary"),
                    "session_id": values.get("session_id") or None,
                    "assessment_id": values.get("assessment_id") or None,
                    "model_resisted": (
                        None if resisted in (None, -1) else bool(resisted)
                    ),
                    "jailbreak_success": bool(values.get("jailbreak_success")),
                    "alert_triggered": bool(values.get("alert_triggered")),
                    "details": details,
                })

        return events

    # --------------------------------------------------
    # CLOSE
    # --------------------------------------------------

    def close(self):
        self.client.close()