# GitHub Setup Guide

## 1) Initialize and Push Repository

From project root:

```bash
git init
git add .
git commit -m "Initial Ghost-Store Guard MVP"
git branch -M main
git remote add origin https://github.com/<your-user>/<your-repo>.git
git push -u origin main
```

## 2) Enable Repository Security Features

In GitHub repository settings:

- Enable **Dependabot alerts**
- Enable **Dependabot security updates**
- Enable **secret scanning**
- Enable **push protection for secrets** (if available)

## 3) Workflows Included

- CI workflow: `.github/workflows/ci.yml`
- Security workflow: `.github/workflows/security.yml`
- CodeQL workflow: `.github/workflows/codeql.yml`
- Dependabot config: `.github/dependabot.yml`

## 4) Recommended Branch Protection (main)

Require:

- Pull request before merge
- At least 1 approving review
- Status checks to pass before merge:
  - `backend`
  - `portal`
- `backend-security`
- `portal-security`
- `analyze (python)` / `analyze (javascript)` from CodeQL
- Dismiss stale approvals on new commits
- Require conversation resolution

## 5) Repository Secrets (if needed)

No secrets are required for current CI, but if you add deployment from GitHub Actions later, add:

- `RAILWAY_TOKEN`
- Any environment-specific deploy secrets

## 6) CODEOWNERS and PR Template

- CODEOWNERS: `.github/CODEOWNERS`
- PR template: `.github/pull_request_template.md`

These are already included for review discipline.

## 7) Dependabot Behavior

Dependabot will open weekly PRs for:

- GitHub Actions
- Python dependencies in `backend/`
- NPM dependencies in `portal/`
- Docker base image dependencies in `backend/`

Review and merge regularly to keep the stack patched.
