from app.services import sessions
from app.services.sessions import ContainmentRegistry


def test_issued_tokens_verify_and_resolve():
    session_id, token = sessions.issue_token()

    assert sessions.verify_token(token) == session_id
    assert sessions.resolve(token) == (session_id, token)


def test_forged_or_missing_tokens_get_a_fresh_session():
    session_id, token = sessions.issue_token()

    for bad in (None, "", "default", "abc.def", token[:-3] + "xxx", f"{session_id}.", "other." + token.split(".")[1]):
        new_id, new_token = sessions.resolve(bad)

        assert new_id != session_id
        assert sessions.verify_token(new_token) == new_id


def test_clients_cannot_choose_or_share_a_session_id():
    a, _ = sessions.resolve("default")
    b, _ = sessions.resolve("default")

    assert a != b


def test_containment_expires_after_ttl(monkeypatch):
    monkeypatch.setenv("CONTAINMENT_TTL_SECONDS", "100")

    now = [0.0]
    registry = ContainmentRegistry(clock=lambda: now[0])

    registry.contain("s")
    assert registry.is_contained("s")

    now[0] = 99
    assert registry.is_contained("s")

    now[0] = 101
    assert not registry.is_contained("s")


def test_hostile_activity_extends_containment(monkeypatch):
    monkeypatch.setenv("CONTAINMENT_TTL_SECONDS", "100")

    now = [0.0]
    registry = ContainmentRegistry(clock=lambda: now[0])

    registry.contain("s")
    now[0] = 90
    registry.record_verdict("s", hostile=True)
    now[0] = 150

    assert registry.is_contained("s")


def test_clean_streak_releases(monkeypatch):
    monkeypatch.setenv("CONTAINMENT_CLEAN_TURNS", "2")

    registry = ContainmentRegistry()
    registry.contain("s")

    assert registry.record_verdict("s", hostile=False) is True
    assert registry.record_verdict("s", hostile=False) is False
    assert not registry.is_contained("s")


def test_hostile_turn_resets_clean_streak(monkeypatch):
    monkeypatch.setenv("CONTAINMENT_CLEAN_TURNS", "2")

    registry = ContainmentRegistry()
    registry.contain("s")

    registry.record_verdict("s", hostile=False)
    registry.record_verdict("s", hostile=True)

    assert registry.record_verdict("s", hostile=False) is True


def test_operator_release():
    registry = ContainmentRegistry()
    registry.contain("s")

    assert registry.release("s") is True
    assert registry.release("s") is False
    assert not registry.is_contained("s")
