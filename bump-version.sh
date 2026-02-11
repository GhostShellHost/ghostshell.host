#!/usr/bin/env bash
# bump-version.sh — update the gs-version badge on all live pages
# Usage: ./bump-version.sh v0.3
# If no arg, just shows current versions.

set -e

PAGES=(
  index.html
  issue/index.html
  register/index.html
  registry/index.html
  handoff/index.html
)

echo "Current versions:"
for f in "${PAGES[@]}"; do
  ver=$(grep -o 'gs-version"[^>]*>[^<]*' "$f" | sed 's/.*>//' || echo "not found")
  echo "  $f  →  $ver"
done

if [[ -z "$1" ]]; then
  echo ""
  echo "To bump: ./bump-version.sh v0.1"
  exit 0
fi

NEW="$1"

for f in "${PAGES[@]}"; do
  sed -i "s|>\(v[0-9][^<]*\)<\/div>|>${NEW}</div>|g" "$f"
done

echo ""
echo "Updated all pages to ${NEW}."
