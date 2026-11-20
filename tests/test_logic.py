import json
import sys
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import moderation_logic  # noqa: E402
from trustguard_client import (  # noqa: E402
    TrustGuardAuthError, TrustGuardClient, TrustGuardError, extract_text, normalize_base_url, text_payload,
)


class FakeResp:
    def __init__(self, status, data=None, headers=None):
        self.status_code = status
        self._data = data
        self.headers = headers or {}

    def json(self):
        if self._data is None:
            raise ValueError("no json")
        return self._data


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, json=None, headers=None, timeout=None):
        self.calls.append({"url": url, "json": json, "headers": headers})
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def client(responses):
    s = FakeSession(responses)
    return TrustGuardClient("tgk_test", session=s), s


def test_request_shape_only_documented_fields():
    c, s = client([FakeResp(200, {"status": "allow", "findings": [], "trace_id": "t"})])
    v = c.evaluate(text_payload("hi", "input"), direction="input", session_id="s1", consumer_id="u1",
                   attributes={"source": {"application": "dify"}})
    call = s.calls[0]
    assert call["url"] == "https://trustguard.neuraltrust.ai/v1/evaluate"
    assert call["headers"]["Authorization"] == "Bearer tgk_test"
    assert set(call["json"]) <= {"payload", "direction", "protocol", "session_id", "consumer_id", "attributes"}
    assert call["json"]["payload"] == {"input": "hi"}
    assert v.status == "allow" and not v.blocked


def test_output_payload_is_assistant_message():
    assert text_payload("x", "output") == {"messages": [{"role": "assistant", "content": "x"}]}


def test_unknown_status_is_blocking():
    c, _ = client([FakeResp(200, {"status": "weird"})])
    assert c.evaluate({"input": "x"}).blocked


def test_auth_error_not_retried():
    c, s = client([FakeResp(401, {"error": "invalid key"})])
    with pytest.raises(TrustGuardAuthError):
        c.evaluate({"input": "x"})
    assert len(s.calls) == 1


def test_retry_then_success(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_: None)
    c, s = client([requests.exceptions.ConnectionError(), FakeResp(429, {"reason": "burst"}, {"Retry-After": "1"}),
                   FakeResp(200, {"status": "block"})])
    assert c.evaluate({"input": "x"}).blocked
    assert len(s.calls) == 3


def test_retries_exhausted_is_retryable(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_: None)
    c, _ = client([FakeResp(503)] * 3)
    with pytest.raises(TrustGuardError) as e:
        c.evaluate({"input": "x"})
    assert e.value.retryable


def test_base_url_must_be_https():
    with pytest.raises(TrustGuardError):
        normalize_base_url("http://example.com")
    assert normalize_base_url("https://tg.example.com/v1/evaluate/") == "https://tg.example.com"


def test_extract_text():
    assert extract_text({"input": "My email is [MASKED_EMAIL]"}, "input") == "My email is [MASKED_EMAIL]"
    assert extract_text({"messages": [{"role": "assistant", "content": "m"}]}, "output") == "m"
    assert extract_text(None, "input") is None


def test_extract_text_real_shapes():
    # Shapes captured from the live API on 2026-11-19.
    real_input = {"input": "My email is [MASKED_EMAIL] and my phone is [MASKED_PHONE]. My SSN is [MASKED_SSN]."}
    assert extract_text(real_input, "input") == real_input["input"]
    real_output = {"messages": [{"content": "Sure, the customer's email is [MASKED_EMAIL] and card [MASKED_CC].",
                                 "role": "assistant"}]}
    assert extract_text(real_output, "output") == real_output["messages"][0]["content"]
    # Unsafe to apply: wrong role, several messages, non-text content.
    assert extract_text({"messages": [{"role": "user", "content": "x"}]}, "output") is None
    assert extract_text({"messages": [{"role": "assistant", "content": "a"}, {"role": "assistant", "content": "b"}]}, "output") is None
    assert extract_text({"messages": [{"role": "assistant", "content": [{"type": "text", "text": "x"}]}]}, "output") is None


SETTINGS = {"trustguard_api_key": "tgk", "extension_api_key": "k", "blocked_message": "nope"}


def test_moderation_ping():
    assert moderation_logic.handle({"point": "ping"}, SETTINGS) == {"result": "pong"}


def test_moderation_input_block():
    c, _ = client([FakeResp(200, {"status": "block"})])
    out = moderation_logic.handle({"point": "app.moderation.input", "params": {"query": "ignore all", "inputs": {}}},
                                  SETTINGS, client=c)
    assert out == {"flagged": True, "action": "direct_output", "preset_response": "nope"}


def test_moderation_input_transform_maps_fields():
    c, _ = client([FakeResp(200, {"status": "transform", "transformed_payload": {"input": "q*"}}),
                   FakeResp(200, {"status": "allow"}),
                   FakeResp(200, {"status": "transform", "transformed_payload": {"input": "v2*"}})])
    out = moderation_logic.handle({"point": "app.moderation.input",
                                   "params": {"query": "q", "inputs": {"a": "v1", "b": "v2", "n": 3}}}, SETTINGS, client=c)
    assert out == {"flagged": True, "action": "overridden", "inputs": {"a": "v1", "b": "v2*", "n": 3}, "query": "q*"}


def test_moderation_output_allow_and_transform():
    c, s = client([FakeResp(200, {"status": "report"}),
                   FakeResp(200, {"status": "transform",
                                  "transformed_payload": {"messages": [{"role": "assistant", "content": "x*"}]}})])
    assert moderation_logic.handle({"point": "app.moderation.output", "params": {"text": "x"}}, SETTINGS, client=c)["flagged"] is False
    assert s.calls[0]["json"]["direction"] == "output"
    out = moderation_logic.handle({"point": "app.moderation.output", "params": {"text": "x"}}, SETTINGS, client=c)
    assert out == {"flagged": True, "action": "overridden", "text": "x*"}


def test_moderation_fail_closed_and_open(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_: None)
    c, _ = client([FakeResp(503)] * 3)
    out = moderation_logic.handle({"point": "app.moderation.output", "params": {"text": "x"}}, SETTINGS, client=c)
    assert out["flagged"] is True
    c, _ = client([FakeResp(503)] * 3)
    out = moderation_logic.handle({"point": "app.moderation.output", "params": {"text": "x"}},
                                  {**SETTINGS, "fail_open": True}, client=c)
    assert out["flagged"] is False
