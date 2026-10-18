#!/usr/bin/env bash
# Install Enclave from source into a directory on your PATH.
#
# Usage:
#   ./scripts/install.sh                 # build + install to /usr/local/bin (or ~/.local/bin)
#   PREFIX=~/.local ./scripts/install.sh # choose the destination
#   ./scripts/install.sh --no-install    # build only, do not copy
#
# Requirements: a Rust toolchain (see rust-toolchain.toml) and, on Linux, the
# usual C toolchain (gcc/make) for the vendored SQLCipher/OpenSSL.
set -euo pipefail

cd "$(dirname "$0")/.."

BIN_NAME="enclave"
NO_INSTALL=0
for arg in "$@"; do
    case "$arg" in
        --no-install) NO_INSTALL=1 ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo not found. Install Rust from https://rustup.rs" >&2
    exit 1
fi

echo "==> Building enclave (release, locked)"
CARGO_INCREMENTAL=0 cargo build --release --locked

BIN="target/release/${BIN_NAME}"
[[ -x "$BIN" ]] || { echo "error: $BIN was not produced" >&2; exit 1; }

if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "==> Ad-hoc signing (keeps the keychain stable across rebuilds)"
    codesign --force --sign - "$BIN" || true
fi

if [[ "$NO_INSTALL" == "1" ]]; then
    echo "==> Build complete: $BIN"
    exit 0
fi

# Pick a destination: $PREFIX/bin, else /usr/local/bin if writable, else ~/.local/bin
if [[ -n "${PREFIX:-}" ]]; then
    DEST_DIR="${PREFIX}/bin"
elif [[ -w /usr/local/bin ]]; then
    DEST_DIR="/usr/local/bin"
else
    DEST_DIR="${HOME}/.local/bin"
fi
mkdir -p "$DEST_DIR"

echo "==> Installing to ${DEST_DIR}/${BIN_NAME}"
install -m 0755 "$BIN" "${DEST_DIR}/${BIN_NAME}"

if command -v "$BIN_NAME" >/dev/null 2>&1; then
    echo "==> Installed. Run: ${BIN_NAME} --help"
else
    echo "==> Installed to ${DEST_DIR}, but it is not on your PATH."
    echo "    Add this to your shell profile:"
    echo "      export PATH=\"${DEST_DIR}:\$PATH\""
fi

echo "==> Config directory (created on first run):"
case "$(uname -s)" in
    Darwin) echo "    ~/Library/Application Support/dev.enclave.enclave" ;;
    *)      echo "    ~/.config/enclave  and  ~/.local/share/enclave" ;;
esac
