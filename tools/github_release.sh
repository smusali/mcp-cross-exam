#!/bin/sh
set -eu
python3 tools/check_changelog.py --notes > release-notes.md
if printf '%s' "$REF_NAME" | grep -q rc; then
  gh release create "$REF_NAME" --title "$REF_NAME" --notes-file release-notes.md --prerelease
else
  gh release create "$REF_NAME" --title "$REF_NAME" --notes-file release-notes.md
fi
