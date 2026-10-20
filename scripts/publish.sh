#!/usr/bin/env bash
# Publish Enclave to GitHub.
#
# Credentials: this repo is pushed over SSH with a DEDICATED, repo-scoped
# deploy key (~/.ssh/id_enclave_deploy, registered on the repository only as a
# deploy key). That key can only touch github.com/tai4a2/enclave — it gives no
# access to any other repository, and no `gh` token with account-wide scopes is
# needed. Remove the deploy key on GitHub to revoke it.
#
# Usage:
#   ./scripts/publish.sh              # push main + tag v0.1.0
#   ./scripts/publish.sh --tag-only   # only push the tag
set -euo pipefail

cd "$(dirname "$0")/.."

REMOTE_URL="git@github-enclave:tai4a2/enclave.git"
TAG="${TAG:-v0.1.0}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' not found"; exit 1; }; }
need git

if [ ! -d .git ]; then echo "error: run this from the repository"; exit 1; fi

if ! grep -q "Host github-enclave" ~/.ssh/config 2>/dev/null; then
  echo "error: ~/.ssh/config has no 'github-enclave' alias."
  echo "Add:"
  echo "  Host github-enclave"
  echo "      HostName github.com"
  echo "      User git"
  echo "      IdentityFile ~/.ssh/id_enclave_deploy"
  echo "      IdentitiesOnly yes"
  exit 1
fi

if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "$REMOTE_URL"
else
  git remote add origin "$REMOTE_URL"
fi
echo "==> remote origin -> $REMOTE_URL"

echo "==> working tree:"
git status --short || true

if [ "${1:-}" != "--tag-only" ]; then
  echo "==> pushing main"
  git push -u origin main
fi

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  echo "==> tag $TAG exists locally"
else
  echo "==> creating tag $TAG"
  git tag -a "$TAG" -m "Enclave ${TAG#v}"
fi
echo "==> pushing tag $TAG"
git push origin "$TAG"

cat <<EOF

==> Pushed. Remaining steps (browser, no credentials shared):
 1. Create the release:      https://github.com/tai4a2/enclave/releases/new?tag=$TAG
    - title "Enclave ${TAG#v}"
    - attach the artifacts built by ./scripts/release.sh:
        dist/enclave
        dist/enclave.sha256
        dist/enclave.cdx.json   (SBOM, if generated)
 2. Enable private vulnerability reporting:
        Settings -> Security -> "Private vulnerability reporting" -> Enable
 3. Check the first CI run:  https://github.com/tai4a2/enclave/actions
EOF
