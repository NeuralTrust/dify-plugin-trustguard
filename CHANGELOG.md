# Changelog

All notable changes to this plugin are documented here. Versions follow `manifest.yaml`.

## 0.1.0 – 2026-11-19

First public release.

- **Evaluate Input** and **Evaluate Output** tools calling the TrustGuard Evaluate API (`POST /v1/evaluate`), with outputs `status`, `blocked`, `safe_text`, `evaluated`, `trace_id` and `findings` for IF/ELSE branching in Workflow and Chatflow apps.
- **Content Moderation endpoint** (`/moderation`) implementing Dify's API-based moderation extension (`ping`, `app.moderation.input`, `app.moderation.output`), mapping `block`/`ask` to a preset response and `transform` to masked text (`overridden`).
- Fail-closed by default; optional fail-open for connection errors, timeouts and HTTP 429/502/503/504 after 3 attempts.
- Tested end to end on Dify Cloud via remote debugging.
