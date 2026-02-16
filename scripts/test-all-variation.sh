#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/test-all-variation.sh [--release]

Runs tests for all Classic McEliece variants. Use --release to run in release mode.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

release_flag=""
if [[ "${1:-}" == "--release" ]]; then
  release_flag="--release"
  shift
fi

if [[ $# -gt 0 ]]; then
  echo "Unexpected arguments: $*" >&2
  usage
  exit 1
fi

CARGO_BIN="${CARGO_BIN:-cargo}"

variants=(
  mceliece348864
  mceliece348864f
  mceliece460896
  mceliece460896f
  mceliece6688128
  mceliece6688128f
  mceliece6960119
  mceliece6960119f
  mceliece8192128
  mceliece8192128f
)

echo "==> generating example keys (if missing)"
CARGO_BIN="$CARGO_BIN" ./scripts/gen-example-keys.sh --all
echo

for variant in "${variants[@]}"; do
  echo "==> cargo test ${release_flag} --features ${variant}"
  "$CARGO_BIN" test ${release_flag} --features "${variant}"
  echo
done
