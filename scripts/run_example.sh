#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/run_example.sh [example] [variant] [-- <example args>]

Runs a single example, auto-generating example key files if needed.

Examples:
  ./scripts/run_example.sh encapsulate_from_file
  ./scripts/run_example.sh encapsulate_static_no_std mceliece348864f
  ./scripts/run_example.sh katkem -- PQCkemKAT_935.req PQCkemKAT_935.rsp
  ./scripts/run_example.sh basic

Notes:
  - Default example is encapsulate_from_file.
  - Default variant is mceliece348864.
  - Key files are generated under examples/keys when required.
EOF
}

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

is_variant() {
  local candidate="$1"
  for v in "${variants[@]}"; do
    if [[ "$candidate" == "$v" ]]; then
      return 0
    fi
  done
  return 1
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

example="${1:-encapsulate_from_file}"
if [[ $# -gt 0 ]]; then
  shift
fi

variant="mceliece348864"
extra_args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --variant)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --variant" >&2
        exit 1
      fi
      variant="$2"
      shift 2
      ;;
    --)
      shift
      extra_args+=("$@")
      break
      ;;
    *)
      if is_variant "$1" && [[ "$variant" == "mceliece348864" ]]; then
        variant="$1"
        shift
      else
        extra_args+=("$1")
        shift
      fi
      ;;
  esac
done

if ! is_variant "$variant"; then
  echo "Unknown variant: $variant" >&2
  usage
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root_dir="$(cd "$script_dir/.." && pwd)"
cd "$root_dir"

if [[ ! -f "$root_dir/examples/${example}.rs" ]]; then
  echo "Unknown example: $example" >&2
  usage
  exit 1
fi

keys_dir="$root_dir/examples/keys"
pk_path="$keys_dir/public_key_${variant}.bin"
sk_path="$keys_dir/secret_key_${variant}.bin"
generated_keys=0

ensure_keys() {
  mkdir -p "$keys_dir"
  if [[ -f "$pk_path" && -f "$sk_path" ]]; then
    return 0
  fi
  echo "Generating example keys for ${variant}..."
  "$CARGO_BIN" run --example encapsulate_from_file --features "${variant}" -- "$pk_path" "$sk_path"
  generated_keys=1
}

features="$variant"
if [[ "$example" == "encapsulate_static_no_std" ]]; then
  features="${variant} example-embedded-keys"
fi

if [[ "$example" == "encapsulate_from_file" ]]; then
  if [[ ${#extra_args[@]} -ge 1 ]]; then
    pk_path="${extra_args[0]}"
  fi
  if [[ ${#extra_args[@]} -ge 2 ]]; then
    sk_path="${extra_args[1]}"
  fi
  extra_args=("$pk_path" "$sk_path")
  ensure_keys
  if [[ "$generated_keys" -eq 1 ]]; then
    exit 0
  fi
elif [[ "$example" == "encapsulate_static_no_std" ]]; then
  ensure_keys
fi

"$CARGO_BIN" run --example "$example" --features "$features" -- "${extra_args[@]}"
