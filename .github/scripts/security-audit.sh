#!/usr/bin/env bash
# Advisory security audit. Runs the Claude CLI against the filter/auth source
# using SECURITY-REVIEW.md as the rubric and security/traversal-corpus.txt as the
# attack corpus, then posts findings as a PR comment. ADVISORY: always exits 0,
# it informs review, it does not block merge. The deterministic gate is each
# template's own test suite.
#
# Env: ANTHROPIC_API_KEY, GH_TOKEN, PR_NUMBER, BASE_SHA, HEAD_SHA.
set -uo pipefail

BASE_SHA="${BASE_SHA:-}"
HEAD_SHA="${HEAD_SHA:-HEAD}"
PR_NUMBER="${PR_NUMBER:-}"

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "No ANTHROPIC_API_KEY (fork PR or key unset) — skipping advisory audit."
  exit 0
fi

if [ -n "$BASE_SHA" ]; then
  CHANGED=$(git diff --name-only "$BASE_SHA" "$HEAD_SHA" || true)
else
  CHANGED=$(git ls-files)
fi

# The repo has three source layouts: Rust filters live at `*/src/lib.rs` (at the
# template root for graphql-protection/harden-cookies/html2md, under a filter
# subdir for edge-sso/edge-totp); auth apps are either flat (edge-sso/auth-app,
# no src/) or `*/otp-app/src/`. Enumerate both layout-agnostically.
mapfile -t FILTERS < <(git ls-files '*/src/lib.rs')
mapfile -t AUTHSRC < <(git ls-files '*auth-app/*' '*otp-app/*' \
  | grep -E '\.(ts|tsx|js|jsx)$' \
  | grep -vE '/(tests?|node_modules|dist|target)/' || true)

in_changed() { printf '%s\n' "$CHANGED" | grep -qxF -- "$1"; }

# When the rubric or audit tooling changed, re-audit every filter (the whole
# path-gating surface), plus any auth-app source this PR touched. Otherwise audit
# only the filter/auth source the PR changed.
FILES=()
if echo "$CHANGED" | grep -qE '^(SECURITY-REVIEW\.md|security/traversal-corpus\.txt|\.github/(workflows/security-audit\.yml|scripts/security-audit\.sh))$'; then
  echo "Audit tooling/checklist changed — auditing all filters + changed auth-app source."
  FILES+=("${FILTERS[@]}")
  for f in "${AUTHSRC[@]}"; do in_changed "$f" && FILES+=("$f"); done
else
  for f in "${FILTERS[@]}" "${AUTHSRC[@]}"; do in_changed "$f" && FILES+=("$f"); done
fi
mapfile -t FILES < <(printf '%s\n' "${FILES[@]}" | awk 'NF' | sort -u)

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "No filter/auth source in scope — nothing to audit."
  exit 0
fi

echo "Auditing ${#FILES[@]} file(s):"
printf '  %s\n' "${FILES[@]}"
FILE_LIST=$(printf '%s\n' "${FILES[@]}")

PROMPT=$(cat <<EOF
You are a security reviewer for a repository of FastEdge edge-proxy templates that
are built and published as products and run on customer edge traffic.

Read SECURITY-REVIEW.md (repo root) — it is the rubric — and
security/traversal-corpus.txt — the canonical attack-path corpus. Then audit each
of these files IN FULL (the whole file, not just recent changes) against every
applicable item in the checklist:

$FILE_LIST

Focus on item 1 (path-gating / auth bypass): any path exemption that skips an
auth or security check MUST reject traversal and encoded-separator sequences
(.., //, \\, %2e, %2f, %5c, %25) BEFORE applying the exemption, and fail closed.
Confirm each path-gating filter rejects the corpus sequences.

For each finding give: checklist item number, file:line, one sentence on the
defect, and the concrete fix. If a file is clean against the checklist, say so.
Be concise and factual. Output GitHub-flavored markdown. Do NOT modify any files.
EOF
)

# ponytail: --allowedTools syntax/version is the tuning knob — adjust on the first
# CI run if the pinned CLI rejects it. Read-only tools only; print mode does not
# prompt, so a disallowed tool is denied rather than hanging the job.
AUDIT=$(claude -p "$PROMPT" --allowedTools "Read" "Grep" "Glob" 2>audit_err.log)
rc=$?
if [ $rc -ne 0 ] || [ -z "$AUDIT" ]; then
  echo "Claude CLI failed (rc=$rc) — advisory audit skipped:"
  cat audit_err.log 2>/dev/null
  exit 0
fi

BODY_FILE=audit_body.md
{
  echo "## 🔒 Security audit (advisory)"
  echo
  echo "Rubric: \`SECURITY-REVIEW.md\` · corpus: \`security/traversal-corpus.txt\` · scope: ${#FILES[@]} file(s)."
  echo "_Advisory — does not block merge. The blocking gate is each template's own test suite._"
  echo
  echo "$AUDIT"
} > "$BODY_FILE"

echo "----- audit -----"; cat "$BODY_FILE"; echo "-----------------"

if [ -n "$PR_NUMBER" ] && [ -n "${GH_TOKEN:-}" ]; then
  gh pr comment "$PR_NUMBER" --body-file "$BODY_FILE" || echo "Comment post failed (non-fatal)."
fi
exit 0
