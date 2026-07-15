# Build state

- Current phase: Day 5 — release-candidate hardening, evaluation, and packaging
- Completed: Days 1–5 implementation; real MCP stdio proxy; deterministic and GPT-judge enforcement; output firewall; tamper-evident audit/reporting; guarded Codex remediation; 35-case evaluation corpus; 12-scenario Attack Lab; static read-only dashboard snapshot; browser tests; container packaging; CI and tagged-release workflows
- Partial: live GPT-5.6 acceptance remains deferred until the selected OpenAI project has active API billing; offline replay and failure-safe behavior are fully tested
- Blocked: live GPT-5.6 smoke previously reached OpenAI but returned HTTP 429 `account is not active`; the user asked to hold the API key for later
- Most recent validation: clean `npm ci`; lint and typecheck clean; 56 tests, 12 integration tests, and 2 Playwright tests pass; evaluation is 35/35; `npm audit` reports zero vulnerabilities; read-only local RC container serves health and downloadable reports
- Packaging: local image `mcp-warden:0.1.0-rc.1`; judge compose defaults to `ghcr.io/mouav/mcp-warden:0.1.0-rc.1`; release workflow publishes archives, checksums, image, and GitHub release from `v*` tags
- Known environment notes: use `npm.cmd` and `codex.cmd` because PowerShell blocks `.ps1` shims; local Playwright uses installed Chrome while CI installs pinned Chromium
- Next tasks: Day 6 documentation polish, license, feedback ID, public repository/release publication, and demo video
- Submission readiness: 84%
