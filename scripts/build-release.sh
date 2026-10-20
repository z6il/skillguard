#!/usr/bin/env bash
# Builds release archives for every platform into dist/.
# Usage: scripts/build-release.sh v0.1.0
set -euo pipefail

version="${1:?usage: build-release.sh <version>}"
rm -rf dist && mkdir -p dist

targets=(
  linux/amd64 linux/arm64
  darwin/amd64 darwin/arm64
  windows/amd64 windows/arm64
)

for t in "${targets[@]}"; do
  os="${t%/*}"; arch="${t#*/}"
  name="skillguard_${version#v}_${os}_${arch}"
  bin="skillguard"; [ "$os" = windows ] && bin="skillguard.exe"
  mkdir -p "dist/$name"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X main.version=${version}" -o "dist/$name/$bin" .
  cp README.md LICENSE "dist/$name/"
  if [ "$os" = windows ]; then
    (cd dist && zip -qr "$name.zip" "$name")
  else
    tar -C dist -czf "dist/$name.tar.gz" "$name"
  fi
  rm -rf "dist/$name"
done

(cd dist && sha256sum skillguard_* > checksums.txt)
ls -la dist
