#!/usr/bin/env bash
# Prints the Atlex coding standards into the agent's context (KAN-16, docs/standards/README.md).
#
#   scripts/standards.sh          # this repo's whole load map (Codex: run before coding)
#   scripts/standards.sh core     # one file (Claude: one SessionStart hook per file, because
#                                 # Claude Code cuts a hook's output at 10,000 characters)
#
# Outside atlex the text is fetched from Atlex-SI/atlex@master with `gh` and cached in the
# gitignored .standards/. A failed fetch falls back to the cache with a warning. It never fails
# the session: it always exits 0.
set -u

# This repo's load map (docs/standards/README.md).
LOAD="core terraform"

SRC_REPO="Atlex-SI/atlex"
SRC_DIR="docs/standards"
FETCH_TIMEOUT_S=10
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CACHE="$ROOT/.standards"

# fetch <name> <out>: succeeds only if gh returned a non-empty file within the timeout.
fetch() {
  local name="$1" out="$2" pid i
  command -v gh >/dev/null 2>&1 || return 1
  gh api -H "Accept: application/vnd.github.raw" \
    "repos/$SRC_REPO/contents/$SRC_DIR/$name.md" >"$out" 2>/dev/null &
  pid=$!
  for ((i = 0; i < FETCH_TIMEOUT_S * 5; i++)); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.2
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    return 1
  fi
  wait "$pid" && [ -s "$out" ]
}

show() {
  local name="$1" tmp
  case "$name" in
    *[!a-z]* | "")
      echo "standards.sh: unknown standards file '$name'" >&2
      return
      ;;
  esac

  # In atlex itself the standards are part of the checkout: read this branch's copy.
  if [ -f "$ROOT/$SRC_DIR/$name.md" ]; then
    echo "<!-- Atlex coding standards: $name.md, from this checkout ($SRC_DIR/) -->"
    cat "$ROOT/$SRC_DIR/$name.md"
    return
  fi

  mkdir -p "$CACHE"
  tmp="$CACHE/.$name.md.part"
  if fetch "$name" "$tmp"; then
    mv -f "$tmp" "$CACHE/$name.md"
    echo "<!-- Atlex coding standards: $name.md, fetched from $SRC_REPO@master -->"
    cat "$CACHE/$name.md"
  elif [ -s "$CACHE/$name.md" ]; then
    rm -f "$tmp"
    echo "WARNING: could not fetch $name.md from $SRC_REPO (is \`gh\` signed in? try \`gh auth status\`)." \
      "Using the cached copy from $(date -r "$CACHE/$name.md" '+%Y-%m-%d %H:%M'); it may be stale."
    cat "$CACHE/$name.md"
  else
    rm -f "$tmp"
    echo "!!! WARNING: ATLEX CODING STANDARDS NOT LOADED: $name.md could not be fetched from" \
      "$SRC_REPO and there is no cached copy. Tell the user. Fix with \`gh auth login\`, then run" \
      "scripts/standards.sh. Until then, read $SRC_DIR/$name.md in $SRC_REPO before writing code. !!!"
  fi
}

if [ "$#" -eq 0 ]; then
  # Intentional word splitting: LOAD is a space-separated list.
  # shellcheck disable=SC2086
  set -- $LOAD
fi
for name in "$@"; do
  show "$name"
  echo
done
exit 0
