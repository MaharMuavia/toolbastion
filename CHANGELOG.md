# Changelog

## 0.1.4 - 2026-07-21

- Added filesystem capability enforcement for denied reads, read-to-write escalation, destructive operations, and scoped Docker writable mounts.
- Upgraded trust baselines to v3 with immutable Docker image or executable/build identity; v1 and v2 baselines fail closed until explicitly migrated.
- Corrected receipt finalization so persistence failures do not lose retry state or leave partial files.
- Added fast-check adversarial properties for path, URL, shell, Unicode, encoding, nesting, and output-injection bypasses.
- Replaced unsupported absolute-security product language with the security-gateway and evidence-layer description.
