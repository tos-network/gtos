#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "Usage: $0 <git-commit-args>" >&2
  echo "Example: $0 -m \"docs: update xyz\"" >&2
  exit 1
fi

"$(dirname "$0")/pre_commit_checks.sh"
git commit "$@"
