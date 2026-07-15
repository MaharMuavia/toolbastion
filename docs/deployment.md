# Deployment and publication handoff

No Git remote is currently configured and the local GitHub CLI credential is invalid, so Day 6 prepares deployment automation without claiming a live deployment.

## Read-only dashboard

`.github/workflows/pages.yml` builds and deploys `apps/dashboard/dist` from `main`. The static app uses relative assets and falls back to committed redacted snapshot files. It has no live enforcement control and no credential.

Owner steps:

1. Create or select the public GitHub repository.
2. Add it as `origin` and push `main`.
3. In repository Settings → Pages, select GitHub Actions as the source if required.
4. Verify the workflow's reported page URL in a private browser window.
5. Confirm `READ-ONLY SNAPSHOT`, all 12 Attack Lab scenarios, navigation anchors, and four downloads.
6. Record that exact URL in the README and submission description.

## Container and GitHub Release

`.github/workflows/release.yml` runs all gates, creates a Linux x64 archive and checksums, publishes a `linux/amd64` GHCR image, and creates a GitHub Release for pushed `v*` tags.

Owner steps after CI and Pages are green:

```bash
git tag -a v0.1.0 -m "MCP Warden v0.1.0"
git push origin main
git push origin v0.1.0
```

Verify the release, checksum, image pull, and keyless compose startup before replacing pending submission links. Never publish `.env.local` or any credential.

## Repository visibility

Public visibility is an account-level state change and must be confirmed by the owner. Before switching visibility, run the secret scan documented in the submission checklist and inspect the full Git history, Actions variables, release assets, screenshots, and issue templates.
