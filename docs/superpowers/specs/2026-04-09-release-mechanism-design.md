# Release Mechanism Design

## Goal

Tag-driven releases that produce a GitHub Release with a Docker image published to GHCR. Version integrity enforced by checking `SERVER_VERSION` in `client.py` matches the git tag.

## Trigger

Push a git tag matching `v*` (e.g., `v3.1.0`).

## Workflow: `.github/workflows/release.yml`

### Jobs

**1. lint** — identical to existing `ci.yml` lint job (ruff check + format).

**2. test** — identical to existing `ci.yml` test job (install `requirements-dev.txt`, run full pytest suite including smoke tests).

**3. release** — runs after lint and test pass. Steps:

1. **Version check**: extract version from tag (strip `v` prefix), grep `SERVER_VERSION` from `client.py` using regex (avoids importing the module which would require falconpy). Fail with clear error if they don't match.
2. **Docker build**: build image using existing `Dockerfile`. Tags: `ghcr.io/roadrunner-security/crowdstrike-mcp:<version>` and `ghcr.io/roadrunner-security/crowdstrike-mcp:latest`.
3. **Docker push**: authenticate to GHCR via `GITHUB_TOKEN`, push both tags.
4. **GitHub Release**: create release on the tag using `gh release create`. Use `--generate-notes` for auto-generated changelog from commits since last tag.

### Permissions

- `contents: write` — create GitHub Release
- `packages: write` — push to GHCR

Both are available via the default `GITHUB_TOKEN` with the permissions block set in the workflow.

## Version Source of Truth

`SERVER_VERSION` in `client.py` remains the runtime version (returned by `/health` endpoint). The release workflow validates it matches the tag — if you forget to bump, the release fails before publishing anything.

## Developer Workflow

```
1. Bump SERVER_VERSION in client.py
2. Commit: "chore: bump version to 3.2.0"
3. git tag v3.2.0
4. git push && git push --tags
5. CI runs lint + test, then builds + publishes
```

## What Doesn't Change

- `ci.yml` — unchanged, still runs on PRs and master pushes
- `client.py` — `SERVER_VERSION` stays where it is, no new version files
- `Dockerfile` — used as-is for the release build

## Future: ECR

When needed, add an ECR push step to the release job. Same image, additional registry. No architectural changes required.
