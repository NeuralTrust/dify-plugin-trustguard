from typing import Any

from dify_plugin import ToolProvider
from dify_plugin.errors.tool import ToolProviderCredentialValidationError

from trustguard_client import TrustGuardClient, TrustGuardError


class TrustGuardProvider(ToolProvider):
    def _validate_credentials(self, credentials: dict[str, Any]) -> None:
        """Send a one-word evaluation, like the n8n node's credential test.

        Note: this creates one record in TrustGuard Activity and counts toward the plan quota.
        TODO(NeuralTrust): if a side-effect-free auth check endpoint exists, use it instead.
        """
        try:
            client = TrustGuardClient(
                api_key=str(credentials.get("api_key", "")),
                base_url=str(credentials.get("base_url") or ""),
            )
            client.evaluate({"input": "ping"}, direction="input", protocol="all",
                            attributes={"source": {"application": "dify-credential-check"}})
        except TrustGuardError as exc:
            raise ToolProviderCredentialValidationError(str(exc)) from None
        except Exception as exc:  # noqa: BLE001
            raise ToolProviderCredentialValidationError(f"Unexpected error: {type(exc).__name__}") from None
