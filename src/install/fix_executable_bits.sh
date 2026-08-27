#!/usr/bin/env bash
set -euo pipefail

ROOT="$(dirname "${BASH_SOURCE[0]}")/../.."

apply_exec_permissions() {
    while IFS= read -r relpath; do
        filepath="$ROOT/$relpath"
        if [ -f "$filepath" ] && [ ! -x "$filepath" ]; then
            echo "Restoring exec permission: $relpath"
            chmod +x "$filepath"
        fi
    done
}

if git -C "$ROOT" rev-parse --is-inside-work-tree &>/dev/null; then
    # local git repo
    git -C "$ROOT" ls-files --stage \
    | grep '^100755' \
    | cut -f2 \
    | apply_exec_permissions
else
    # fallback: GitHub API
    curl -fsSL "https://api.github.com/repos/fkie-cad/FACT_core/git/trees/master?recursive=1" \
    | jq -r '.tree[] | select(.mode == "100755") | .path' \
    | apply_exec_permissions
fi
