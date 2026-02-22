#!/usr/bin/env bash
set -euo pipefail

# Minimal, repo-agnostic pre-commit checks for doc-only commits.
git diff --cached --check
