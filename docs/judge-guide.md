# Judge guide

The judge artifact is an offline, read-only review experience. It serves the completed fixture session, Attack Lab, downloadable reports, and evaluation summary without an API key or source compilation.

## Prebuilt container

Install Docker Desktop or Docker Engine with Compose, then run:

```bash
export TOOLBASTION_API_TOKEN="$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n')"
docker compose -f docker-compose.judge.yml pull
docker compose -f docker-compose.judge.yml up
```

Open `http://127.0.0.1:4782/#token=$TOOLBASTION_API_TOKEN`. The fragment is never sent in HTTP requests; the dashboard uses it only as an in-memory bearer credential. The compose file binds only to localhost, runs a read-only filesystem, enables `no-new-privileges`, and loads the recorded offline corpus. Stop and remove it with:

```bash
docker compose -f docker-compose.judge.yml down
```

To test a local source build instead of the published image, override the image name:

```bash
docker build -t toolbastion:local .
TOOLBASTION_IMAGE=toolbastion:local TOOLBASTION_PULL_POLICY=never docker compose -f docker-compose.judge.yml up
```

In PowerShell, set `$env:TOOLBASTION_IMAGE="toolbastion:local"`, `$env:TOOLBASTION_PULL_POLICY="never"`, and `$env:TOOLBASTION_API_TOKEN=[Convert]::ToBase64String((1..48 | ForEach-Object { Get-Random -Maximum 256 })) -replace '[+/=]', ''` before the compose command.

## Integrity and scope

- The banner says `OFFLINE FIXTURE REPLAY` or `READ-ONLY SNAPSHOT`.
- No OpenAI key is required, used for model calls, or included in the image or snapshot.
- Downloads contain redacted audit data only.
- This artifact demonstrates deterministic and recorded semantic behavior; it does not claim to run a live MCP target.

Live GPT-5.6 mode is optional and should be run from a source checkout with the user's own active project credential. Never bake credentials into an image.

## Verify the recorded snapshot

The GitHub Release contains a source archive generated from the tagged commit; extract it, install its locked dependencies, and prepare the artifact before verification:

```powershell
npm.cmd ci
npm.cmd run artifact:prepare
npm.cmd run verify:snapshot
```

The command exits nonzero if the v2 audit start/event/seal lifecycle, sequence, previous-hash linkage, event hashes, displayed session, regenerated reports, scenarios, or fixture summary disagree. The hash chain is tamper-evident, not a digital signature or externally anchored attestation.
