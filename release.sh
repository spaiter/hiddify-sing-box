#!/usr/bin/env bash
# Release script: tags, builds, and pushes a versioned Docker image.
# Works on Linux and Windows (Git Bash / MSYS2 / WSL).
#
# Usage:
#   ./release.sh           # auto-generates version from today's date
#   ./release.sh 2026.02.19.3  # use explicit version

set -euo pipefail

REPO="ghcr.io/spaiter/hiddify-sing-box"

# Determine version
if [ -n "${1:-}" ]; then
  VERSION="$1"
else
  TODAY=$(date +%Y.%m.%d)
  # Find the next revision for today
  REV=1
  while git tag -l "${TODAY}.${REV}" | grep -q .; do
    REV=$((REV + 1))
  done
  VERSION="${TODAY}.${REV}"
fi

echo "==> Version: ${VERSION}"

# Git tag and push
echo "==> Creating git tag..."
git tag "${VERSION}"
git push origin "${VERSION}"

# Docker build and push
echo "==> Building Docker image..."
docker build --build-arg VERSION="${VERSION}" \
  -t "${REPO}:${VERSION}" \
  -t "${REPO}:latest" \
  .

echo "==> Pushing Docker images..."
docker push "${REPO}:${VERSION}"
docker push "${REPO}:latest"

echo "==> Done! Released ${VERSION}"
echo "    ${REPO}:${VERSION}"
echo "    ${REPO}:latest"
