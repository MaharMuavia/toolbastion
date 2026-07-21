# Changelog

## Unreleased

- Added trust-baseline v2 with reviewed per-tool filesystem, network, command, subprocess, and destructive capability contracts.
- Enforce mode now fails closed for missing or changed contracts, unsupported allowlisted egress, and uncontained declared capabilities.
- Added `toolbastion trust migrate --yes` for explicit v1 baseline rebuilds.
- Corrected receipt timing to capture acceptance once and finalization once, with deterministic-clock coverage.
- Removed raw command executable projection from judge envelopes and renamed the local context field from intent to category.
- Added capability and adversarial validation coverage plus per-category evaluation output.
