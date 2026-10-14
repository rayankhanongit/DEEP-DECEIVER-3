from app.database.influx import InfluxDBService


def test_query_forensic_events():

    service = InfluxDBService()

    events = service.query_events(
        time_range="-24h",
        limit=10
    )

    assert isinstance(events, list)

    service.close()

def test_forensic_event_structure():

    service = InfluxDBService()

    events = service.query_events(
        time_range="-24h",
        limit=10
    )

    if events:
        event = events[0]

        assert "timestamp" in event
        assert "session_id" in event
        assert "attack_category" in event
        assert "intent" in event
        assert "final_risk_score" in event
        assert "route" in event
        assert "action" in event

    service.close()