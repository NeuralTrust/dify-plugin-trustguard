"""Dify API-based Content Moderation extension backed by TrustGuard.

Dify contract: https://docs.dify.ai/en/cloud/use-dify/workspace/api-extension/api-extension
and https://docs.dify.ai/en/cloud/use-dify/workspace/api-extension/moderation-api-extension
  - POST, Authorization: Bearer <API Extension key>
  - point=ping -> {"result": "pong"}
  - point=app.moderation.input  params {app_id, inputs, query}
  - point=app.moderation.output params {app_id, text}  (streamed output arrives in ~100-char chunks)
  - response {flagged, action: direct_output|overridden, preset_response | inputs/query | text}
"""

from __future__ import annotations

import hmac
import json
from collections.abc import Mapping
from typing import Any

from werkzeug import Request, Response

from dify_plugin import Endpoint

import moderation_logic


def _json(data: dict[str, Any], status: int = 200) -> Response:
    return Response(json.dumps(data), status=status, content_type="application/json")


class TrustGuardModerationEndpoint(Endpoint):
    def _invoke(self, r: Request, values: Mapping, settings: Mapping) -> Response:
        expected = str(settings.get("extension_api_key") or "")
        scheme, _, token = (r.headers.get("Authorization") or "").partition(" ")
        if not expected or scheme.lower() != "bearer" or not hmac.compare_digest(token.strip(), expected):
            return _json({"error": "unauthorized"}, status=401)
        try:
            body = r.get_json(force=True, silent=False) or {}
        except Exception:  # noqa: BLE001
            return _json({"error": "invalid JSON body"}, status=400)
        if not isinstance(body, dict):
            return _json({"error": "invalid JSON body"}, status=400)
        return _json(moderation_logic.handle(body, settings))
