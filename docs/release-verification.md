# Release verification

Run the following on a clean, network-capable release runner and record each exit code in a release-specific verification summary:

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

This workspace's current local Docker script reported access-denied errors for the Docker configuration/buildx directories, and `npm audit` could not reach its registry endpoint or write its cache log. Neither is a passed release gate.
