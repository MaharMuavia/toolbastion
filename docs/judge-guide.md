# Judge guide

The judge artifact is an offline, read-only review experience. It serves the completed fixture session, Attack Lab, downloadable reports, and evaluation summary without an API key or source compilation.

## Prebuilt container

Install Docker Desktop or Docker Engine with Compose, then run:

```bash
docker compose -f docker-compose.judge.yml pull
docker compose -f docker-compose.judge.yml up
```

Open `http://127.0.0.1:4782`. The compose file binds only to localhost, runs a read-only filesystem, enables `no-new-privileges`, and loads the recorded offline corpus. Stop and remove it with:

```bash
docker compose -f docker-compose.judge.yml down
```

Before the first public image is published, build the exact release-candidate image locally and override the image name:

```bash
docker build -t mcp-warden:0.1.0-rc.1 .
WARDEN_IMAGE=mcp-warden:0.1.0-rc.1 WARDEN_PULL_POLICY=never docker compose -f docker-compose.judge.yml up
```

In PowerShell, set `$env:WARDEN_IMAGE="mcp-warden:0.1.0-rc.1"` and `$env:WARDEN_PULL_POLICY="never"` before the compose command.

## Integrity and scope

- The banner says `OFFLINE FIXTURE REPLAY` or `READ-ONLY SNAPSHOT`.
- No OpenAI credential is required or read.
- Downloads contain redacted audit data only.
- This artifact demonstrates deterministic and recorded semantic behavior; it does not claim to run a live MCP target.

Live GPT-5.6 mode is optional and should be run from a source checkout with the user's own active project credential. Never bake credentials into an image.

## Verify the recorded audit chain

From a source or release checkout after the build:

```powershell
npm.cmd run verify:snapshot
```

The command exits nonzero if sequence, previous-hash linkage, event hash, or parsed event validation fails. The hash chain is tamper-evident, not a digital signature or externally anchored attestation.
