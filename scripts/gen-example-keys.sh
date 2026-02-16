#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/gen-example-keys.sh [--all] [variant...]

Generate missing example key files under examples/keys.

Examples:
  ./scripts/gen-example-keys.sh
  ./scripts/gen-example-keys.sh mceliece348864f
  ./scripts/gen-example-keys.sh --all
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

CARGO_BIN="${CARGO_BIN:-cargo}"

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
  variants=("mceliece348864")
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root_dir="$(cd "$script_dir/.." && pwd)"
keys_dir="$root_dir/examples/keys"
mkdir -p "$keys_dir"

for variant in "${variants[@]}"; do
  pk_path="$keys_dir/public_key_${variant}.bin"
  sk_path="$keys_dir/secret_key_${variant}.bin"
  if [[ -f "$pk_path" && -f "$sk_path" ]]; then
    continue
  fi
  echo "Generating example keys for ${variant}..."
  "$CARGO_BIN" run --example encapsulate_from_file --features "${variant}" -- "$pk_path" "$sk_path"
done
