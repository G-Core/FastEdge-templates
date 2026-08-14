#!/usr/bin/env bash
# check-manifest-completeness.sh — every template must be discoverable by the plugin
#
# A "template" is any top-level directory containing a registry.json anywhere under it
# (that's what makes it a Gcore-portal-publishable app). This script fails the build if
# such a directory isn't referenced by any fastedge-plugin-source/manifest.json 'sources'
# entry — i.e. a new template was added but nobody wired it into the plugin's catalog.
#
# This is what turns "developer forgot to update the plugin" into a CI failure instead of
# a silent gap. See fastedge-plugin-source/.generation-config.md for what to add when this
# fails.
#
# Usage: check-manifest-completeness.sh [repo-root]
set -euo pipefail

REPO_ROOT="${1:-.}"
MANIFEST="${REPO_ROOT}/fastedge-plugin-source/manifest.json"

if [[ ! -f "$MANIFEST" ]]; then
  echo "ERROR: $MANIFEST not found" >&2
  exit 1
fi

# All file paths declared across every 'sources' entry, as a newline-separated list.
declared_files=$(jq -r '.sources | to_entries[] | (.value.files? // [])[]' "$MANIFEST")
errors=0

while IFS= read -r -d '' registry_file; do
  # Template dir = top-level directory component of the registry.json's path.
  template_dir="${registry_file#"$REPO_ROOT"/}"
  template_dir="${template_dir%%/*}"

  readme="${template_dir}/README.md"
  if ! grep -qxF "$readme" <<<"$declared_files"; then
    echo "ERROR: '${template_dir}/' has a registry.json but '${readme}' is not listed in" \
      "any fastedge-plugin-source/manifest.json 'sources' entry." >&2
    echo "  Add it to the 'catalog' source (and write context/integration.md + a new" \
      "source entry if this template needs origin-side code). See" \
      "fastedge-plugin-source/.generation-config.md." >&2
    errors=$((errors + 1))
  fi
done < <(find "$REPO_ROOT" -mindepth 2 -name registry.json -not -path '*/node_modules/*' -print0)

if [[ "$errors" -gt 0 ]]; then
  echo "Manifest completeness check FAILED: $errors template(s) missing from manifest.json." >&2
  exit 1
fi

echo "Manifest completeness check passed."
