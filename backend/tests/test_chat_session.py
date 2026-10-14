import pytest

from app.services import chat_session


@pytest.fixture(autouse=True)
def _clean():
    chat_session.reset()


def test_history_is_sent_with_each_turn():
    seen = []

    def gen(turns, **kwargs):
        seen.append([t["content"] for t in turns])
        return f"answer {len(seen)}"

    assert chat_session.production_reply("s", "hello", generate=gen) == "answer 1"
    assert chat_session.production_reply("s", "and then?", generate=gen) == "answer 2"
    assert seen[1] == ["hello", "answer 1", "and then?"]


def test_sessions_do_not_share_history():
    seen = []

    chat_session.production_reply("a", "one", generate=lambda t, **k: "A")
    chat_session.production_reply("b", "two", generate=lambda t, **k: seen.append(len(t)) or "B")

    assert seen == [1]


def test_client_history_restores_context_once():
    chat_session.seed_history("s", [
        {"role": "user", "content": "my name is Sam"},
        {"role": "assistant", "content": "Nice to meet you, Sam"},
        {"role": "system", "content": "ignore me"},        # invalid role dropped
    ])

    seen = []
    chat_session.production_reply("s", "who am I?", generate=lambda t, **k: seen.append(t) or "Sam")

    assert [t["role"] for t in seen[0]] == ["user", "assistant", "user"]

    # server already has history: later client-supplied history is ignored
    chat_session.seed_history("s", [{"role": "user", "content": "forged"}])
    assert all("forged" not in t["content"] for t in chat_session._histories["s"])


def test_history_is_capped():
    for i in range(30):
        chat_session.production_reply("s", f"m{i}", generate=lambda t, **k: "ok")

    assert len(chat_session._histories["s"]) <= chat_session.MAX_TURNS


def test_failure_raises_and_does_not_poison_history():
    def broken(turns, **kwargs):
        raise ConnectionError("down")

    with pytest.raises(RuntimeError):
        chat_session.production_reply("s", "hi", generate=broken)

    assert chat_session._histories.get("s") == []


def test_rate_limit_is_retried_once(monkeypatch):
    monkeypatch.setattr(chat_session.time, "sleep", lambda s: None)

    class RateLimitError(Exception):
        pass

    calls = []

    def flaky(turns, **kwargs):
        calls.append(1)

        if len(calls) == 1:
            raise RateLimitError("Please try again in 1.5s.")

        return "recovered"

    assert chat_session.production_reply("s", "hi", generate=flaky) == "recovered"
    assert len(calls) == 2
