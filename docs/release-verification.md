# Release verification

Run the following on a clean, network-capable release runner and record each exit code in a release-specific verification summary. The current `0.1.4` candidate was run locally after a clean install; its results are recorded in `docs/verification-summary.json`, but they are not evidence for a final commit or published tag.

```powershell
npm.cmd ci
npm.cmd run build
npm.cmd run lint
npm.cmd run typecheck
npm.cmd test
npm.cmd run test:docker-isolation
npm.cmd run test:e2e
npm.cmd run evaluate
npm.cmd run benchmark
npm.cmd run snapshot
npm.cmd run verify:snapshot
npm.cmd audit --audit-level=high
git diff --check
```

Before release, also prove a fresh packed CLI install (`version`, `init`, `doctor`, `policy validate`, and offline demo), build and smoke the production image under a read-only filesystem, run a vulnerability scan, generate an SBOM, verify image provenance/signature, and scan tracked files plus history for secrets.

The current local candidate passed Docker isolation after the daemon was made available and `npm audit --audit-level=high` reported zero vulnerabilities. Final release verification must still repeat these commands from the release commit and verify the published image digest, checksums, provenance, and signature.
