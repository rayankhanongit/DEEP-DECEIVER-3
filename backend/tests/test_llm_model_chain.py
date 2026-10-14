import pytest

from app.services import llm


class RateLimitError(Exception):
    pass


class FakeClient:
    def __init__(self, behaviour):
        self.calls = []
        self.behaviour = behaviour

        outer = self

        class Completions:
            def create(self, model, **kwargs):
                outer.calls.append(model)
                return outer.behaviour(model)

        class Chat:
            completions = Completions()

        self.chat = Chat()


def reply(text):
    class M:
        content = text

    class C:
        message = M()

    class R:
        choices = [C()]

    return R()


@pytest.fixture(autouse=True)
def _models(monkeypatch):
    monkeypatch.setattr(llm, "CHAT_MODELS", ["primary", "backup"])
    llm._blocked_until.clear()


def test_falls_back_to_next_model_on_rate_limit(monkeypatch):
    def behaviour(model):
        if model == "primary":
            raise RateLimitError("Rate limit ... Please try again in 1m17.3s.")

        return reply("from backup")

    fake = FakeClient(behaviour)
    monkeypatch.setattr(llm, "_client", fake)

    assert llm.generate_chat([{"role": "user", "content": "hi"}]) == "from backup"
    assert fake.calls == ["primary", "backup"]


def test_rate_limited_model_is_skipped_afterwards(monkeypatch):
    def behaviour(model):
        if model == "primary":
            raise RateLimitError("try again in 1m17.3s")

        return reply("ok")

    fake = FakeClient(behaviour)
    monkeypatch.setattr(llm, "_client", fake)

    llm.generate_chat([{"role": "user", "content": "one"}])
    llm.generate_chat([{"role": "user", "content": "two"}])

    assert fake.calls == ["primary", "backup", "backup"]


def test_other_errors_are_not_swallowed(monkeypatch):
    def behaviour(model):
        raise ValueError("bad request")

    monkeypatch.setattr(llm, "_client", FakeClient(behaviour))

    with pytest.raises(ValueError):
        llm.generate_chat([{"role": "user", "content": "hi"}])


def test_all_models_limited_raises(monkeypatch):
    def behaviour(model):
        raise RateLimitError("try again in 2s")

    monkeypatch.setattr(llm, "_client", FakeClient(behaviour))

    with pytest.raises(RateLimitError):
        llm.generate_chat([{"role": "user", "content": "hi"}])


def test_retry_hint_parsing():
    assert llm._retry_seconds(Exception("try again in 1m17.328s")) == pytest.approx(77.328)
    assert llm._retry_seconds(Exception("try again in 850ms")) == pytest.approx(0.85)
    assert llm._retry_seconds(Exception("no hint")) == 60.0
