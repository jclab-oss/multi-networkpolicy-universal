#!/bin/sh
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"

if [ -n "${KUBECTL:-}" ]; then
  build_manifest() {
    "${KUBECTL}" kustomize "$1"
  }
elif [ -n "${KUSTOMIZE:-}" ]; then
  build_manifest() {
    "${KUSTOMIZE}" build "$1"
  }
elif command -v kubectl >/dev/null 2>&1; then
  build_manifest() {
    kubectl kustomize "$1"
  }
elif command -v kustomize >/dev/null 2>&1; then
  build_manifest() {
    kustomize build "$1"
  }
else
  echo "kubectl or kustomize is required to generate manifests" >&2
  exit 1
fi

DEPLOY_MANIFEST="${DEPLOY_MANIFEST:-${ROOT}/deploy.yml}"
E2E_MANIFEST="${E2E_MANIFEST:-${ROOT}/e2e/multi-network-policy-nftables-e2e.yml}"
KATA_DEPLOY_MANIFEST="${KATA_DEPLOY_MANIFEST:-${ROOT}/deploy-kata.yml}"
E2E_KATA_MANIFEST="${E2E_KATA_MANIFEST:-${ROOT}/e2e/multi-network-policy-nftables-e2e-kata.yml}"

build_manifest "${ROOT}/config/manager/overlays/default" > "${DEPLOY_MANIFEST}"
build_manifest "${ROOT}/config/manager/overlays/e2e" > "${E2E_MANIFEST}"
build_manifest "${ROOT}/config/manager/overlays/kata" > "${KATA_DEPLOY_MANIFEST}"
build_manifest "${ROOT}/config/manager/overlays/e2e-kata" > "${E2E_KATA_MANIFEST}"
