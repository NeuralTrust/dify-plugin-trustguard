"""Minimal client for the NeuralTrust TrustGuard Evaluate API.

Source of truth: https://docs.neuraltrust.ai/trustguard/api/evaluate

POST {base_url}/v1/evaluate
Authorization: Bearer <collector API key>   (tgk_...)

Only documented top-level fields are sent, because the endpoint decodes strictly
and rejects unknown top-level keys with HTTP 400:
payload, direction, protocol, session_id, consumer_id, attributes
(gateway_id / collector_key are only for service-token callers and are not used).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import requests

DEFAULT_BASE_URL = "https://trustguard.neuraltrust.ai"
EVALUATE_PATH = "/v1/evaluate"
DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_ATTEMPTS = 3
MAX_RETRY_AFTER_SECONDS = 5.0
USER_AGENT = "neuraltrust-dify-plugin/0.1.0"

# Statuses documented for the reduced verdict.
STATUS_ALLOW = "allow"
STATUS_REPORT = "report"
STATUS_TRANSFORM = "transform"
STATUS_ASK = "ask"
STATUS_BLOCK = "block"
STATUS_SKIP = "skip"
KNOWN_STATUSES = {STATUS_ALLOW, STATUS_REPORT, STATUS_TRANSFORM, STATUS_ASK, STATUS_BLOCK, STATUS_SKIP}
# Statuses that must stop the content. Unknown statuses are treated as blocking (fail closed).
BLOCKING_STATUSES = {STATUS_BLOCK, STATUS_ASK}

RETRYABLE_HTTP = {429, 502, 503, 504}


class TrustGuardError(Exception):
    """Evaluation could not be completed. Message never contains the API key."""

    def __init__(self, message: str, *, status_code: int | None = None, retryable: bool = False):
        super().__init__(message)
        self.status_code = status_code
        self.retryable = retryable


class TrustGuardAuthError(TrustGuardError):
    pass


@dataclass
class Verdict:
    status: str
    transformed_payload: dict[str, Any] | None
    findings: list[dict[str, Any]] = field(default_factory=list)
    trace_id: str = ""
    request_id: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.status in BLOCKING_STATUSES or self.status not in KNOWN_STATUSES

    @property
    def transformed(self) -> bool:
        return self.status == STATUS_TRANSFORM and isinstance(self.transformed_payload, dict)


def normalize_base_url(value: str | None) -> str:
    base = (value or "").strip() or DEFAULT_BASE_URL
    base = base.rstrip("/")
    if base.endswith(EVALUATE_PATH):
        base = base[: -len(EVALUATE_PATH)]
    parsed = urlparse(base)
    if parsed.scheme != "https" or not parsed.netloc:
        raise TrustGuardError("TrustGuard Base URL must be an https:// origin, e.g. https://trustguard.neuraltrust.ai")
    return base


def text_payload(text: str, direction: str) -> dict[str, Any]:
    """Build the payload for a single piece of text.

    Per the docs: input may be sent as {"input": "..."}; on direction=output the
    completion must be sent as an assistant message, otherwise Toxicity and
    Custom Moderation skip it.
    """
    if direction == "output":
        return {"messages": [{"role": "assistant", "content": text}]}
    return {"input": text}


def extract_text(transformed_payload: dict[str, Any] | None, direction: str) -> str | None:
    """Return the masked text from transformed_payload, mirroring text_payload().

    Verified live against TrustGuard (2026-11-19, DLP detector in Transform mode):
    transformed_payload mirrors the request payload shape, e.g.
      request {"input": "..."}                                  -> {"input": "My email is [MASKED_EMAIL] ..."}
      request {"messages": [{"role": "assistant", "content": ...}]} -> {"messages": [{"content": "... [MASKED_EMAIL] ...", "role": "assistant"}]}
    and it is null when nothing was transformed.
    """
    if not isinstance(transformed_payload, dict):
        return None
    if isinstance(transformed_payload.get("input"), str):
        return transformed_payload["input"]
    messages = transformed_payload.get("messages")
    if not isinstance(messages, list) or len(messages) != 1 or not isinstance(messages[0], dict):
        # We always send exactly one message; anything else cannot be applied safely.
        return None
    expected_role = "assistant" if direction == "output" else "user"
    message = messages[0]
    if message.get("role") not in (None, expected_role):
        return None
    content = message.get("content")
    return content if isinstance(content, str) else None


class TrustGuardClient:
    def __init__(self, api_key: str, base_url: str | None = None, timeout: float = DEFAULT_TIMEOUT_SECONDS,
                 session: requests.Session | None = None):
        api_key = (api_key or "").strip()
        if not api_key:
            raise TrustGuardAuthError("TrustGuard API key is required.")
        self._api_key = api_key
        self.base_url = normalize_base_url(base_url)
        self.timeout = timeout
        self._session = session or requests.Session()

    def evaluate(self, payload: dict[str, Any], *, direction: str = "input", protocol: str = "llm",
                 session_id: str | None = None, consumer_id: str | None = None,
                 attributes: dict[str, Any] | None = None) -> Verdict:
        if direction not in ("input", "output"):
            raise TrustGuardError(f"Invalid direction: {direction}")
        body: dict[str, Any] = {"payload": payload, "direction": direction, "protocol": protocol}
        if session_id:
            body["session_id"] = session_id
        if consumer_id:
            body["consumer_id"] = consumer_id
        if attributes:
            body["attributes"] = attributes
        data = self._post(body)
        status = str(data.get("status", "")).lower()
        return Verdict(
            status=status,
            transformed_payload=data.get("transformed_payload"),
            findings=data.get("findings") or [],
            trace_id=str(data.get("trace_id") or ""),
            request_id=str(data.get("request_id") or ""),
            raw=data,
        )

    def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        url = self.base_url + EVALUATE_PATH
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        }
        last_error: TrustGuardError | None = None
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                resp = self._session.post(url, json=body, headers=headers, timeout=self.timeout)
            except requests.exceptions.SSLError as exc:
                # TLS problems are configuration faults, never retried / failed open.
                raise TrustGuardError(f"TLS error contacting TrustGuard: {type(exc).__name__}") from None
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
                last_error = TrustGuardError(f"TrustGuard unreachable: {type(exc).__name__}", retryable=True)
                self._sleep(attempt, None)
                continue

            if resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError:
                    raise TrustGuardError("TrustGuard returned a non-JSON 200 response.", status_code=200) from None
                if not isinstance(data, dict) or "status" not in data:
                    raise TrustGuardError("TrustGuard response has no 'status' field.", status_code=200)
                return data

            detail = self._error_detail(resp)
            if resp.status_code in (401, 403):
                raise TrustGuardAuthError(
                    f"TrustGuard rejected the API key (HTTP {resp.status_code}). {detail}".strip(),
                    status_code=resp.status_code,
                )
            if resp.status_code in RETRYABLE_HTTP:
                last_error = TrustGuardError(f"TrustGuard HTTP {resp.status_code}. {detail}".strip(),
                                             status_code=resp.status_code, retryable=True)
                self._sleep(attempt, resp.headers.get("Retry-After"))
                continue
            raise TrustGuardError(f"TrustGuard HTTP {resp.status_code}. {detail}".strip(), status_code=resp.status_code)
        assert last_error is not None
        raise last_error

    @staticmethod
    def _error_detail(resp: requests.Response) -> str:
        # Error responses carry { "error", "trace_id", "request_id" }; 402/429 also carry "reason".
        try:
            data = resp.json()
        except ValueError:
            return ""
        if not isinstance(data, dict):
            return ""
        parts = [str(data[k]) for k in ("error", "reason") if data.get(k)]
        if data.get("trace_id"):
            parts.append(f"trace_id={data['trace_id']}")
        return " ".join(parts)[:300]

    @staticmethod
    def _sleep(attempt: int, retry_after: str | None) -> None:
        if attempt >= MAX_ATTEMPTS:
            return
        delay = 0.25 * (2 ** (attempt - 1))
        if retry_after:
            try:
                delay = min(float(retry_after), MAX_RETRY_AFTER_SECONDS)
            except ValueError:
                pass
        time.sleep(delay)


def dify_attributes(model_name: str | None = None, model_provider: str | None = None,
                    application: str = "dify") -> dict[str, Any]:
    """Documented attribute dimensions: source.application, model.{name,provider}."""
    attrs: dict[str, Any] = {"source": {"application": application}}
    model: dict[str, str] = {}
    if model_name:
        model["name"] = model_name
    if model_provider:
        model["provider"] = model_provider
    if model:
        attrs["model"] = model
    return attrs
