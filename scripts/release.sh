#!/usr/bin/env bash
# Build, (ad-hoc) sign and package a release of Enclave.
#
# Produces:
#   target/release/enclave            the binary
#   dist/enclave                      the binary used by the user (ad-hoc signed on macOS)
#   dist/enclave.sha256               its SHA-256
#   dist/enclave.cdx.json             SBOM (if cargo-cyclonedx is installed)
#
# Usage: ./scripts/release.sh [version]
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${1:-$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)}"
echo "==> Building enclave ${VERSION} (release)"

# Reproducible-ish build: pinned toolchain (rust-toolchain.toml), no incremental,
# locked dependencies.
CARGO_INCREMENTAL=0 cargo build --release --locked

mkdir -p dist
cp target/release/enclave dist/enclave

if [[ "$(uname -s)" == "Darwin" ]]; then
    # Ad-hoc signature: stable identity per build, so macOS does not re-prompt
    # the keychain for every rebuild. Replace with a Developer ID for release.
    if [[ -n "${ENCLAVE_SIGN_IDENTITY:-}" ]]; then
        echo "==> Signing with identity ${ENCLAVE_SIGN_IDENTITY}"
        codesign --force --options runtime --sign "${ENCLAVE_SIGN_IDENTITY}" dist/enclave
    else
        echo "==> Ad-hoc signing dist/enclave"
        codesign --force --sign - dist/enclave
    fi
fi

echo "==> SHA-256"
if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 dist/enclave | tee dist/enclave.sha256
else
    sha256sum dist/enclave | tee dist/enclave.sha256
fi

if command -v cargo-cyclonedx >/dev/null 2>&1; then
    echo "==> Generating SBOM (CycloneDX)"
    cargo cyclonedx --format json >/dev/null 2>&1 || true
    find . -maxdepth 2 -name "*.cdx.json" -exec cp {} dist/enclave.cdx.json \; 2>/dev/null || true
fi

echo "==> Done: dist/enclave (v${VERSION})"