# Deployment and publication

ToolBastion publishes three independently verifiable artifacts from GitHub Actions.

## Read-only security console

`.github/workflows/pages.yml` runs the canonical artifact preparation pipeline, verifies that it does not change the committed snapshot, then deploys `apps/dashboard/dist` from `main` to [GitHub Pages](https://maharmuavia.github.io/toolbastion/). The static application uses relative assets, reads only committed redacted fixtures, exposes no enforcement controls, and contains no credential.

Verify the workflow URL in an unauthenticated browser and confirm the `READ-ONLY SNAPSHOT` label, twelve Attack Lab scenarios, navigation anchors, and four report downloads. The dashboard remains outside the enforcement path.

## Container and GitHub Release

`.github/workflows/release.yml` reruns every release gate for `v*` tags, builds the isolated target probe, proves that its loopback request cannot reach a host collector, regenerates and verifies the committed snapshot, scans tracked files for selected OpenAI, GitHub, and AWS access-key patterns, builds a source archive from the tagged commit, emits SHA-256 checksums and an SPDX SBOM, publishes `ghcr.io/maharmuavia/toolbastion:<tag>`, and creates a GitHub Release. All third-party GitHub Actions are pinned to immutable commit SHAs.

For `v0.1.0`, verify all of the following:

```bash
gh release view v0.1.0 --repo MaharMuavia/toolbastion
docker pull ghcr.io/maharmuavia/toolbastion:v0.1.0
docker compose -f docker-compose.judge.yml up
```

The container must run as a non-root user, accept a read-only root filesystem, and serve the clearly labelled offline fixture without an OpenAI key. Remote API binds require a `TOOLBASTION_API_TOKEN` base64url secret of 32-256 characters. Supply it through the deployment secret store, open the dashboard using `#token=<secret>` (the fragment is not transmitted), and never expose the container port beyond a trusted network boundary. The Compose mapping publishes `127.0.0.1:4782`; the CLI's `--expose` flag is explicit in the image command.

## Publication gate

Before any public push, inspect tracked files and full history for credentials, run the complete validation suite, and inspect screenshots at full resolution. Never publish `.env.local`, raw runtime audit directories, or credentials in Actions variables, releases, fixtures, screenshots, or issue templates.
