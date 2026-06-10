# Release Mechanism Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a tag-driven GitHub Actions release workflow that gates on lint+test, validates version consistency, builds a Docker image to GHCR, and creates a GitHub Release.

**Architecture:** Single workflow file triggered by `v*` tag pushes. Reuses existing CI patterns for lint/test, then adds a release job with version check, Docker build+push, and GitHub Release creation.

**Tech Stack:** GitHub Actions, Docker, GHCR, `gh` CLI

**Spec:** `docs/superpowers/specs/2026-04-09-release-mechanism-design.md`

---

## Chunk 1: Release workflow

### Task 1: Create release workflow

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Create the release workflow**

```yaml
name: Release

on:
  push:
    tags: ["v*"]

permissions:
  contents: write
  packages: write

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install ruff
        run: pip install ruff>=0.8.0
      - name: Check linting
        run: ruff check .
      - name: Check formatting
        run: ruff format --check .

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install dependencies
        run: pip install -r requirements-dev.txt
      - name: Run tests
        run: pytest tests/ -v --tb=short

  release:
    needs: [lint, test]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Extract version from tag
        id: version
        run: echo "version=${GITHUB_REF_NAME#v}" >> "$GITHUB_OUTPUT"

      - name: Verify SERVER_VERSION matches tag
        run: |
          code_version=$(grep -oP 'SERVER_VERSION = "\K[^"]+' client.py)
          tag_version="${{ steps.version.outputs.version }}"
          if [ "$code_version" != "$tag_version" ]; then
            echo "::error::Version mismatch: client.py has '$code_version' but tag is 'v$tag_version'"
            echo "Update SERVER_VERSION in client.py to '$tag_version' before tagging."
            exit 1
          fi
          echo "Version check passed: $tag_version"

      - name: Log in to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push Docker image
        uses: docker/build-push-action@v6
        with:
          context: .
          push: true
          tags: |
            ghcr.io/${{ github.repository }}:${{ steps.version.outputs.version }}
            ghcr.io/${{ github.repository }}:latest

      - name: Create GitHub Release
        run: gh release create "$GITHUB_REF_NAME" --generate-notes
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

- [ ] **Step 2: Validate workflow syntax locally**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && python -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))" && echo "Valid YAML"`
Expected: "Valid YAML"

- [ ] **Step 3: Run lint to confirm no project issues**

Run: `cd /home/wwebster/projects/command-center/sectors/CrowdStrike/crowdstrike-mcp && ruff check . && ruff format --check .`
Expected: All checks passed

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "feat: add tag-driven release workflow with GHCR and GitHub Release"
```

- [ ] **Step 5: Push**

```bash
git push
```
