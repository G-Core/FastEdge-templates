#!/usr/bin/env bash
# validate-contract.sh — validate a fastedge-plugin-source/ contract directory
#
# Vendored verbatim from fastedge-plugin/scripts/sync/validate-contract.sh — do not
# hand-edit; re-copy from there if it changes.
#
# Validates manifest.json schema and contract integrity.
# Used in two places:
#   1. Source repo CI — catches broken docs before merge
#   2. Plugin pipeline — after sparse checkout, before generation
#
# Usage: validate-contract.sh <path-to-contract-dir> [repo-root]
#
#   contract-dir: path to fastedge-plugin-source/ directory (contains manifest.json)
#   repo-root:    (optional) path to the repo root. When provided, Rule 3 verifies
#                 that source files declared in manifest.json actually exist.
#                 When omitted, only manifest structure is validated.
#
# Exit codes:
#   0  all checks passed (or advisory-mode warnings only)
#   1  strict validation failure or manifest parse error
#
# Sourcing: when sourced as a library (BASH_SOURCE != $0), only functions are
# defined — no execution occurs. Used by test scripts for unit tests.
set -euo pipefail

# ── Helpers ───────────────────────────────────────────────────────────────────

ERRORS=0
WARNINGS=0

_fail() {
  echo "VALIDATION ERROR: $*" >&2
  ERRORS=$((ERRORS + 1))
}

_warn() {
  echo "VALIDATION WARNING: $*" >&2
  WARNINGS=$((WARNINGS + 1))
}

# _report <mode> <message>
# In strict mode, calls _fail. In advisory mode, calls _warn.
_report() {
  local mode="$1"; shift
  if [[ "$mode" == "strict" ]]; then
    _fail "$@"
  else
    _warn "$@"
  fi
}

# ── Path safety ──────────────────────────────────────────────────────────────

# _is_safe_path <path>
# Returns 0 if the path is safe to use, 1 if it contains traversal,
# absolute paths, or .git refs. Used by other scripts that source this file.
_is_safe_path() {
  local p="$1"
  # Reject absolute paths (source files must be relative to repo root)
  if [[ "$p" == /* ]]; then
    return 1
  fi
  # Reject path traversal (.. as a segment anywhere in the path)
  if [[ "$p" =~ (^|/)\.\.(/|$) ]]; then
    return 1
  fi
  # Reject .git/ access
  if [[ "$p" =~ (^|/)\.git(/|$) ]]; then
    return 1
  fi
  return 0
}

# ── Validation functions ─────────────────────────────────────────────────────

# check_manifest_exists <contract-dir>
# Rule 1: manifest.json must exist and parse as valid JSON.
check_manifest_exists() {
  local contract_dir="$1"
  local manifest="${contract_dir}/manifest.json"

  if [[ ! -f "$manifest" ]]; then
    _fail "Rule 1: manifest.json not found in ${contract_dir}"
    return 1
  fi

  if ! jq empty "$manifest" 2>/dev/null; then
    _fail "Rule 1: manifest.json is not valid JSON"
    return 1
  fi

  return 0
}

# check_schema_version <manifest-path>
# Rule 2: $schema field must be present and match expected pattern.
check_schema_version() {
  local manifest="$1"
  local schema
  schema=$(jq -r '."$schema" // empty' "$manifest")

  if [[ -z "$schema" ]]; then
    _fail "Rule 2: manifest.json missing \$schema field"
    return
  fi

  if [[ "$schema" != https://fastedge-plugin-source/manifest/* ]]; then
    _fail "Rule 2: \$schema must match 'https://fastedge-plugin-source/manifest/*', got: ${schema}"
  fi
}

# check_required_sources <manifest-path> <mode> <strict-fields-json> [repo-root]
# Rule 3: All sources entries with required:true must have non-empty files arrays.
# When repo_root is provided, also checks that each file exists and is non-empty.
check_required_sources() {
  local manifest="$1" mode="$2" strict_fields="$3" repo_root="${4:-}"

  while IFS=$'\t' read -r key files_json required; do
    [[ "$required" != "true" ]] && continue

    # Determine effective mode for this entry
    local effective_mode="$mode"
    if printf '%s' "$strict_fields" | jq -e --arg k "$key" 'index($k) != null' >/dev/null 2>&1; then
      effective_mode="strict"
    fi

    # Validate that files is an array before iterating
    local files_type
    files_type=$(echo "$files_json" | jq -r 'type')
    if [[ "$files_type" != "array" ]]; then
      _report "$effective_mode" "Rule 3: Required source '${key}' has 'files' of type '${files_type}', expected array"
      continue
    fi

    # Check that files array is non-empty
    local file_count
    file_count=$(echo "$files_json" | jq 'length')
    if [[ "$file_count" -eq 0 ]]; then
      _report "$effective_mode" "Rule 3: Required source '${key}' has empty files array"
      continue
    fi

    # Reject unsafe paths (traversal or .git access) — always an error regardless of mode
    local has_unsafe=false
    while IFS= read -r file; do
      if ! _is_safe_path "$file"; then
        _fail "Rule 3: Unsafe file path in source '${key}': ${file}"
        has_unsafe=true
      fi
    done < <(echo "$files_json" | jq -r '.[]')
    [[ "$has_unsafe" == true ]] && continue

    # If repo_root provided, check each file exists
    if [[ -n "$repo_root" ]]; then
      while IFS= read -r file; do
        local filepath="${repo_root}/${file}"
        if [[ ! -f "$filepath" ]]; then
          _report "$effective_mode" "Rule 3: Required file missing: ${file} (source key: ${key})"
        elif [[ ! -s "$filepath" ]]; then
          _report "$effective_mode" "Rule 3: Required file is empty: ${file} (source key: ${key})"
        fi
      done < <(echo "$files_json" | jq -r '.[]')
    fi
  done < <(jq -r '.sources | to_entries[] | [.key, (.value.files | tojson), (.value.required // false | tostring)] | @tsv' "$manifest")
}

# check_target_mapping <manifest-path>
# Rule 5: All target_mapping reference_file paths must start with 'plugins/'.
check_target_mapping() {
  local manifest="$1"

  while IFS=$'\t' read -r source_key ref_file; do
    if [[ "$ref_file" != plugins/* ]]; then
      _fail "Rule 5: target_mapping reference_file must start with 'plugins/': ${ref_file} (source key: ${source_key})"
    fi
  done < <(jq -r '.target_mapping | to_entries[] | [.key, .value.reference_file] | @tsv' "$manifest")
}

# check_sources_mapping_consistency <manifest-path>
# Rule 6: Every key in target_mapping must have a corresponding sources entry.
check_sources_mapping_consistency() {
  local manifest="$1"

  while IFS= read -r mapping_key; do
    local found
    found=$(jq -r --arg k "$mapping_key" '.sources | has($k)' "$manifest")
    if [[ "$found" != "true" ]]; then
      _warn "Rule 6: target_mapping key '${mapping_key}' has no matching sources entry"
    fi
  done < <(jq -r '.target_mapping | keys[]' "$manifest")
}

# ── Main validation ──────────────────────────────────────────────────────────

validate_contract() {
  local contract_dir="$1"
  local repo_root="${2:-}"

  ERRORS=0
  WARNINGS=0

  if [[ ! -d "$contract_dir" ]]; then
    _fail "Contract directory not found: ${contract_dir}"
    echo "Contract validation FAILED with $ERRORS error(s)." >&2
    return 1
  fi

  local manifest="${contract_dir}/manifest.json"

  # Rule 1: manifest exists and parses
  if ! check_manifest_exists "$contract_dir"; then
    echo "Contract validation FAILED with $ERRORS error(s)." >&2
    return 1
  fi

  # Read validation config
  local mode
  mode=$(jq -r '.validation.mode // "advisory"' "$manifest")
  if [[ "$mode" != "advisory" && "$mode" != "strict" ]]; then
    _warn "Unknown validation.mode '${mode}' in manifest.json — expected 'advisory' or 'strict'. Defaulting to advisory."
    mode="advisory"
  fi
  local strict_fields
  strict_fields=$(jq '.validation.strict_fields // []' "$manifest")

  # Rule 2: schema version
  check_schema_version "$manifest"

  # Structural checks: .sources and .target_mapping must be objects if present.
  local has_sources=true has_target_mapping=true

  if ! jq -e '.sources | type == "object"' "$manifest" >/dev/null 2>&1; then
    _fail "manifest.json '.sources' is missing or not an object — Rules 3, 6 cannot run"
    has_sources=false
  fi

  if ! jq -e '.target_mapping | type == "object"' "$manifest" >/dev/null 2>&1; then
    _fail "manifest.json '.target_mapping' is missing or not an object — Rules 5, 6 cannot run"
    has_target_mapping=false
  fi

  # Rule 3: required sources have files, and files exist if repo_root provided
  if [[ "$has_sources" == true ]]; then
    check_required_sources "$manifest" "$mode" "$strict_fields" "$repo_root"
  fi

  # Rule 5: target_mapping paths start with plugins/
  if [[ "$has_target_mapping" == true ]]; then
    check_target_mapping "$manifest"
  fi

  # Rule 6: sources/mapping consistency
  if [[ "$has_sources" == true && "$has_target_mapping" == true ]]; then
    check_sources_mapping_consistency "$manifest"
  fi

  # Summary
  if [[ "$ERRORS" -gt 0 ]]; then
    echo "Contract validation FAILED with $ERRORS error(s), $WARNINGS warning(s)." >&2
    return 1
  fi

  if [[ "$WARNINGS" -gt 0 ]]; then
    echo "Contract validation passed with $WARNINGS warning(s)."
  else
    echo "Contract validation passed."
  fi
  return 0
}

# ── Entry point ───────────────────────────────────────────────────────────────

_validate_contract_main() {
  local CONTRACT_DIR="${1:-}"
  local REPO_ROOT="${2:-}"

  if [[ -z "$CONTRACT_DIR" ]]; then
    echo "ERROR: No contract directory path provided." >&2
    echo "Usage: $0 <path-to-contract-dir> [repo-root]" >&2
    exit 1
  fi

  validate_contract "$CONTRACT_DIR" "$REPO_ROOT"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  _validate_contract_main "$@"
fi
