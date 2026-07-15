# Deployment and publication

ToolBastion publishes three independently verifiable artifacts from GitHub Actions.

## Read-only security console

`.github/workflows/pages.yml` builds `apps/dashboard/dist` from `main` and deploys it to [GitHub Pages](https://maharmuavia.github.io/toolbastion/). The static application uses relative assets, reads only committed redacted fixtures, exposes no enforcement controls, and contains no credential.

Verify the workflow URL in an unauthenticated browser and confirm the `READ-ONLY SNAPSHOT` label, twelve Attack Lab scenarios, navigation anchors, and four report downloads. The dashboard remains outside the enforcement path.

## Container and GitHub Release

`.github/workflows/release.yml` reruns every release gate for `v*` tags, builds a Linux x64 archive, emits SHA-256 checksums, publishes `ghcr.io/maharmuavia/toolbastion:<tag>`, and creates a GitHub Release.

For `v0.1.0`, verify all of the following:

```bash
gh release view v0.1.0 --repo MaharMuavia/toolbastion
docker pull ghcr.io/maharmuavia/toolbastion:v0.1.0
docker compose -f docker-compose.judge.yml up
```

The container must run as a non-root user, bind only to `127.0.0.1`, accept a read-only root filesystem, and serve the clearly labelled offline fixture without an OpenAI key.

## Publication gate

Before any public push, inspect tracked files and full history for credentials, run the complete validation suite, and inspect screenshots at full resolution. Never publish `.env.local`, raw runtime audit directories, or credentials in Actions variables, releases, fixtures, screenshots, or issue templates.
