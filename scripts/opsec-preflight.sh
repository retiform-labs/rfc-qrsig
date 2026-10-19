#!/usr/bin/env bash
# QRSIG repo opsec preflight: sweep tracked files + the proposed commit
# message for private markers. Marker list is NEVER committed - it is
# injected via OPSEC_MARKERS_FILE (gitignored, mode 600) or OPSEC_MARKERS.
# A missing marker list = LOUD WARNING + FAIL, never a silent pass.
set -u
fail=0
MARKERS_FILE="${OPSEC_MARKERS_FILE:-.opsec-markers}"
if [ -n "${OPSEC_MARKERS:-}" ]; then
  MARKER_SOURCE="env"
elif [ -f "$MARKERS_FILE" ]; then
  MARKER_SOURCE="$MARKERS_FILE"
else
  echo "opsec-preflight: WARNING - no marker list found ($OPSEC_MARKERS env or $MARKERS_FILE)."
  echo "opsec-preflight: FAIL - refusing to run a scan that checks nothing."
  exit 1
fi
# Letter-boundary lookarounds; case-insensitive. Matches the calibration
# lessons from the reference implementation of this gate elsewhere.
pattern_of() {
  local m
  m="$(echo "$1" | sed 's/[][\.*^$()+?{|]/\\&/g')"
  printf '(?i)(?<![A-Za-z])%s(?![A-Za-z0-9])' "$m"
}
sweep() {
  local what="$1"; shift
  local hits=0
  while IFS= read -r marker; do
    [ -z "$marker" ] && continue
    local pat
    pat="$(pattern_of "$marker")"
    local out
    out=$(grep -aPi "$pat" "$@" 2>/dev/null || true)
    if [ -n "$out" ]; then
      echo "opsec-preflight: MARKER HIT [$marker] in $what:"
      echo "$out" | head -5
      hits=$((hits+1))
    fi
  done < <(echo "$MARKERS" | tr ',' '\n')
  echo "opsec-preflight: $what sweep done - $hits marker(s) hit"
  [ "$hits" -eq 0 ]
}
MARKERS="$(cat "$MARKERS_FILE" 2>/dev/null || echo "$OPSEC_MARKERS")"
# 1) tracked files (staged set, not the working tree)
mapfile -t files < <(git diff --cached --name-only 2>/dev/null; git ls-files 2>/dev/null)
if [ ${#files[@]} -gt 0 ]; then
  sweep "tracked-files" "${files[@]}" || fail=1
fi
# 2) commit message (the separate surface - filter-repo never fixes this)
if [ -f "$MARKERS_FILE" ] || [ -n "${OPSEC_MARKERS:-}" ]; then
  if [ -f ".git/COMMIT_EDITMSG" ]; then
    sweep "commit-message" ".git/COMMIT_EDITMSG" || fail=1
  fi
fi
if [ "$fail" -ne 0 ]; then
  echo "opsec-preflight: FAILED - do not push until resolved."
  exit 1
fi
echo "opsec-preflight: clean."
exit 0
