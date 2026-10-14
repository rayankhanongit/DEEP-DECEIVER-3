from app.api.soc import get_events, get_stats


def test_get_events():

    result = get_events(
        time_range="-24h",
        limit=10
    )

    assert "count" in result
    assert "events" in result
    assert isinstance(result["events"], list)


def test_get_stats():

    result = get_stats(
        time_range="-24h"
    )

    assert "total_events" in result
    assert "threats_detected" in result
    assert "honeypot_activations" in result
    assert "production_requests" in result
    assert "average_risk_score" in result
    assert "attack_categories" in result

    assert result["total_events"] >= 0
    assert result["threats_detected"] >= 0
    assert result["honeypot_activations"] >= 0