from __future__ import annotations

from collections.abc import Generator
from typing import Any

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from trustguard_client import (
    DEFAULT_TIMEOUT_SECONDS,
    STATUS_ALLOW,
    TrustGuardAuthError,
    TrustGuardClient,
    TrustGuardError,
    dify_attributes,
    extract_text,
    text_payload,
)


def _str(value: Any) -> str:
    return "" if value is None else str(value).strip()


class EvaluateTool(Tool):
    """Shared logic for Evaluate Input / Evaluate Output."""

    direction = "input"

    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage, None, None]:
        text = tool_parameters.get("text")
        text = "" if text is None else str(text)
        if not text.strip():
            # Fail closed like the n8n node: an empty payload would score "allow".
            raise ValueError("`text` is empty. Map it to the prompt or response you want to evaluate.")

        try:
            timeout = float(tool_parameters.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS)
        except (TypeError, ValueError):
            timeout = DEFAULT_TIMEOUT_SECONDS
        timeout = max(1.0, min(timeout, 60.0))
        fail_open = bool(tool_parameters.get("fail_open", False))

        creds = self.runtime.credentials
        client = TrustGuardClient(api_key=_str(creds.get("api_key")), base_url=_str(creds.get("base_url")),
                                  timeout=timeout)
        try:
            verdict = client.evaluate(
                text_payload(text, self.direction),
                direction=self.direction,
                protocol="llm",
                session_id=_str(tool_parameters.get("session_id")) or None,
                consumer_id=_str(tool_parameters.get("consumer_id")) or None,
                attributes=dify_attributes(model_name=_str(tool_parameters.get("model_name")) or None),
            )
        except TrustGuardAuthError:
            raise
        except TrustGuardError as exc:
            if fail_open and exc.retryable:
                result = {"status": STATUS_ALLOW, "blocked": False, "safe_text": text, "evaluated": False,
                          "trace_id": "", "findings": [], "error": str(exc)}
                yield from self._emit(result)
                return
            raise

        if verdict.blocked:
            safe_text = ""
        elif verdict.transformed:
            masked = extract_text(verdict.transformed_payload, self.direction)
            if masked is None:
                raise ValueError("TrustGuard returned a transform verdict whose payload could not be applied "
                                 f"safely (trace_id={verdict.trace_id}).")
            safe_text = masked
        else:
            safe_text = text

        result = {
            "status": verdict.status,
            "blocked": verdict.blocked,
            "safe_text": safe_text,
            "evaluated": True,
            "trace_id": verdict.trace_id,
            "findings": verdict.findings,
        }
        yield from self._emit(result)

    def _emit(self, result: dict[str, Any]) -> Generator[ToolInvokeMessage, None, None]:
        for key in ("status", "blocked", "safe_text", "evaluated", "trace_id", "findings"):
            yield self.create_variable_message(key, result[key])
        yield self.create_json_message(result)
        yield self.create_text_message(result["status"])
