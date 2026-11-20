"""Pure mapping between Dify's moderation extension contract and TrustGuard (unit-testable)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from trustguard_client import TrustGuardClient, TrustGuardError, dify_attributes, extract_text

DEFAULT_BLOCKED_MESSAGE = "This content was blocked by NeuralTrust TrustGuard."
UNAVAILABLE_MESSAGE = "Content could not be checked by NeuralTrust TrustGuard. Please try again later."


def _not_flagged() -> dict[str, Any]:
    return {"flagged": False, "action": "direct_output", "preset_response": ""}


def _blocked(message: str) -> dict[str, Any]:
    return {"flagged": True, "action": "direct_output", "preset_response": message}


def handle(body: Mapping[str, Any], settings: Mapping[str, Any], client: TrustGuardClient | None = None) -> dict[str, Any]:
    point = body.get("point")
    params = body.get("params") or {}
    if point == "ping":
        return {"result": "pong"}
    if point not in ("app.moderation.input", "app.moderation.output"):
        # Unsupported extension points (e.g. app.external_data_tool.query) are not handled.
        return {"error": f"unsupported point: {point}"}

    blocked_message = str(settings.get("blocked_message") or DEFAULT_BLOCKED_MESSAGE)
    fail_open = bool(settings.get("fail_open", False))
    try:
        client = client or TrustGuardClient(
            api_key=str(settings.get("trustguard_api_key") or ""),
            base_url=str(settings.get("trustguard_base_url") or ""),
        )
    except TrustGuardError:
        return _blocked(UNAVAILABLE_MESSAGE)

    app_id = str(params.get("app_id") or "")
    attributes = dify_attributes()
    try:
        if point == "app.moderation.input":
            return _moderate_input(client, params, attributes, app_id, blocked_message)
        return _moderate_output(client, params, attributes, app_id, blocked_message)
    except TrustGuardError as exc:
        if fail_open and exc.retryable:
            return _not_flagged()
        return _blocked(UNAVAILABLE_MESSAGE)


def _moderate_input(client: TrustGuardClient, params: Mapping[str, Any], attributes: dict[str, Any],
                    app_id: str, blocked_message: str) -> dict[str, Any]:
    inputs = params.get("inputs") or {}
    query = params.get("query")
    # Evaluate the chat query and every non-empty string input variable, one call each,
    # so a transform verdict maps back to the exact field it masked.
    fields: list[tuple[str, str]] = []
    if isinstance(query, str) and query.strip():
        fields.append(("__query__", query))
    if isinstance(inputs, Mapping):
        for key, value in inputs.items():
            if isinstance(value, str) and value.strip():
                fields.append((str(key), value))
    if not fields:
        return _not_flagged()

    new_inputs = dict(inputs) if isinstance(inputs, Mapping) else {}
    new_query = query
    overridden = False
    for key, text in fields:
        # TODO(verify): Dify does not send conversation_id/user to moderation extensions,
        # so session grouping is per app only. app_id is NOT a conversation key; we leave session_id unset.
        verdict = client.evaluate({"input": text}, direction="input", protocol="llm", attributes=attributes)
        if verdict.blocked:
            return _blocked(blocked_message)
        if verdict.transformed:
            masked = extract_text(verdict.transformed_payload, "input")
            if masked is None:
                return _blocked(blocked_message)  # fail closed: cannot apply masking safely
            overridden = True
            if key == "__query__":
                new_query = masked
            else:
                new_inputs[key] = masked
    if overridden:
        return {"flagged": True, "action": "overridden", "inputs": new_inputs, "query": new_query}
    return _not_flagged()


def _moderate_output(client: TrustGuardClient, params: Mapping[str, Any], attributes: dict[str, Any],
                     app_id: str, blocked_message: str) -> dict[str, Any]:
    text = params.get("text")
    if not isinstance(text, str) or not text.strip():
        return _not_flagged()
    verdict = client.evaluate({"messages": [{"role": "assistant", "content": text}]}, direction="output",
                              protocol="llm", attributes=attributes)
    if verdict.blocked:
        return _blocked(blocked_message)
    if verdict.transformed:
        masked = extract_text(verdict.transformed_payload, "output")
        if masked is None:
            return _blocked(blocked_message)
        return {"flagged": True, "action": "overridden", "text": masked}
    return _not_flagged()
