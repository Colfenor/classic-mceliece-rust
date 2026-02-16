#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./run-examples.sh [--all] [variant...]

Runs the file-based example (encapsulate_from_file).

Examples:
  ./run-examples.sh
  ./run-examples.sh mceliece348864f
  ./run-examples.sh --all
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

variants=()
if [[ "${1:-}" == "--all" ]]; then
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
  shift
elif [[ $# -gt 0 ]]; then
  variants=("$@")
else
  variants=("mceliece6688128")
fi

for variant in "${variants[@]}"; do
  echo "== ${variant} =="
  cargo run --example encapsulate_from_file --features "${variant}"
done
