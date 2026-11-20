# Privacy Policy

This policy describes how the **NeuralTrust TrustGuard** plugin for Dify handles data.

## Data the plugin processes

- **Content to be evaluated**: the text you map into the Evaluate Input / Evaluate Output tools, or, when the Content Moderation endpoint is enabled, the end-user query and input variables (`app.moderation.input`) and the model output (`app.moderation.output`) that Dify sends to the endpoint. This content can contain personal data if your end users type it.
- **Optional identifiers** you choose to map: Session ID, Consumer ID (for example a Dify user ID or e-mail) and model name.
- **Credentials**: the TrustGuard API key and, for the endpoint, the API Extension key. They are stored by the Dify platform as secret fields and are used only to authenticate requests.

## How the data is used and where it is sent

- The plugin sends the content and the optional identifiers over HTTPS to the NeuralTrust TrustGuard Evaluate API (`POST {base_url}/v1/evaluate`, default `https://trustguard.neuraltrust.ai`, or the self-hosted origin you configure) solely to obtain a security verdict (allow, report, transform, ask, block, skip).
- NeuralTrust is the only third-party service the plugin contacts. No analytics, advertising or tracking services are used.

## Storage, logging and retention

- The plugin itself does not store or log the evaluated content or the credentials. It keeps no local database or persistent storage.
- **NeuralTrust stores evaluation records.** TrustGuard records evaluated traffic and findings in your NeuralTrust workspace (shown in **Activity**), with credentials redacted before storage. Retention is a per-team entitlement; the documented default for TrustGuard is 365 days and a shorter window can be requested. See https://docs.neuraltrust.ai/trustguard/data-handling.
- Dify may log tool inputs and outputs according to your Dify deployment settings.

## Third-party privacy policy

- NeuralTrust privacy policy: https://neuraltrust.ai/privacy-policy

## Contact

For privacy questions about this plugin, contact alessandro.pignati@neuraltrust.ai or open an issue on the source repository: https://github.com/NeuralTrust/dify-plugin-trustguard.
