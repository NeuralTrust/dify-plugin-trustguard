# NeuralTrust TrustGuard for Dify

**Author:** NeuralTrust · **Version:** 0.1.0 · **Type:** tool (+ endpoint)
**Source:** https://github.com/NeuralTrust/dify-plugin-trustguard
**Contact:** alessandro.pignati@neuraltrust.ai

## Overview

[NeuralTrust TrustGuard](https://docs.neuraltrust.ai/trustguard/overview) is runtime security for AI agents. It inspects prompts and responses against a policy you build in the NeuralTrust console (jailbreak / prompt injection, toxicity, custom topic moderation, PII and secret masking, indirect prompt injection, URL and document screening) and returns a verdict: `allow`, `report`, `transform`, `ask`, `block` or `skip`.

This plugin brings TrustGuard into Dify in two ways:

| Capability | Where | What it enforces |
| - | - | - |
| **Evaluate Input** tool | Workflow / Chatflow nodes, Agents | Check a prompt before the LLM node and branch on `blocked` |
| **Evaluate Output** tool | Workflow / Chatflow nodes, Agents | Check the LLM answer before it reaches the user |
| **Content Moderation endpoint** | Chatbot, Agent, Chatflow apps via *Content Moderation → API Extension* | Block or mask user input and model output without changing the app graph |

## Requirements

- A NeuralTrust account with TrustGuard.
- An **Application → REST API** collector (console: *Agent Security → Collectors → Catalog*). Create its API key (`tgk_…`) on the **Auth** tab (shown once) and assign a policy on the **Policies** tab. Add Input **and** Output phase rules if you want both directions evaluated.
- Network egress from Dify to your TrustGuard base URL (default `https://trustguard.neuraltrust.ai`; the exact value is on the collector's **Connection** tab).

Tip: start the policy in **Observe** mode, review results in **Activity**, then switch to **Enforce**.

## Setup

1. Install the plugin from the Dify Marketplace.
2. Open **Plugins → NeuralTrust TrustGuard → Authorize** and enter:
   - **TrustGuard API Key**: your `tgk_…` collector key.
   - **TrustGuard Base URL**: leave the default unless you use a regional, self-hosted or hybrid deployment.
3. Saving runs a one-word test evaluation (it appears in TrustGuard Activity).

## Usage

### 1. Workflow / Chatflow guard (recommended)

```
Start → TrustGuard: Evaluate Input (text = {{sys.query}})
      → IF/ELSE  blocked == true  → Answer "Request blocked"
                 else             → LLM (prompt = safe_text) → TrustGuard: Evaluate Output (text = LLM.text)
                                   → IF/ELSE blocked == true → Answer "Response withheld" / else → Answer safe_text
```

Tool outputs:

| Variable | Meaning |
| - | - |
| `status` | `allow`, `report`, `transform`, `ask`, `block` or `skip` |
| `blocked` | `true` for `block` and `ask` (and any unknown verdict) |
| `safe_text` | Masked text on `transform`, empty when blocked, otherwise the original text |
| `evaluated` | `false` only when TrustGuard was unreachable and *Fail Open* was enabled |
| `trace_id` | Same ID as the finding in TrustGuard **Activity** |
| `findings` | Raw findings returned by TrustGuard |

Optional parameters: **Session ID** (map `{{sys.conversation_id}}` so multi-turn attacks are grouped), **Consumer ID** (map `{{sys.user_id}}` for per-consumer policies), **Model Name**, **Fail Open on Unreachable** (off = fail closed), **Timeout**.

The workflow wiring enforces the verdict: always connect the `blocked == true` branch away from the LLM. Used as an Agent tool, the verdict is visible to the model but not enforced.

### 2. Content Moderation (no graph changes)

1. In the plugin page, open **Endpoints → +**, fill in the TrustGuard API key, an **API Extension Key** (a long random string you choose), the blocked message and fail-open preference. Copy the generated `/moderation` URL.
2. In Dify, **Settings → API Extension → Add**: paste the URL as *API Endpoint* and the same API Extension Key as *API Key*. Dify sends a `ping` to verify it.
3. In your app, **Features → Content Moderation**: choose *API Extension*, select it, and enable *Review Input Content* and/or *Review Output Content*.

Mapping: `block`/`ask` → `flagged: true, action: direct_output` with your blocked message; `transform` → `action: overridden` with the masked query, inputs or text; `allow`/`report`/`skip` → not flagged.

Limitations: Dify sends streamed output to moderation in ~100-character chunks, so output detectors see partial text; Dify does not pass conversation or user IDs to moderation extensions, so turns are not grouped by session.

## Failure behavior

- Defaults to **fail closed**: if TrustGuard cannot be reached, the tool node fails and the moderation endpoint returns a blocked response.
- With *Fail Open on Unreachable*, only connection errors, timeouts and HTTP 429/502/503/504 (after 3 attempts) let content through. HTTP 401/403, other 4xx/5xx and TLS errors always fail.

## Privacy

See [PRIVACY.md](./PRIVACY.md) and the [NeuralTrust privacy policy](https://neuraltrust.ai/privacy-policy). Evaluated content is sent to NeuralTrust TrustGuard and stored in your NeuralTrust workspace according to its [data handling](https://docs.neuraltrust.ai/trustguard/data-handling) policy.

## Development

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt pytest
pytest -q tests
# live test against TrustGuard: export your tgk_ collector key in the shell first
# (variable name in e2e_test.py; the key is never printed)
python e2e_test.py
# remote debugging: copy .env.example to .env, fill in the values shown in Dify (Plugins > Debugging)
python -m main
# package
cd .. && dify plugin package ./dify-plugin-trustguard -o trustguard-0.1.0.difypkg
```

## Support

Open an issue at https://github.com/NeuralTrust/dify-plugin-trustguard/issues or e-mail alessandro.pignati@neuraltrust.ai.

## License

Apache-2.0, see [LICENSE](./LICENSE).
