#!/bin/sh
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

DEPLOY_RENDER="${TMPDIR}/deploy.yml"
E2E_RENDER="${TMPDIR}/multi-network-policy-nftables-e2e.yml"
KATA_DEPLOY_RENDER="${TMPDIR}/deploy-kata.yml"
E2E_KATA_RENDER="${TMPDIR}/multi-network-policy-nftables-e2e-kata.yml"
DEPLOY_MANIFEST="${DEPLOY_RENDER}" E2E_MANIFEST="${E2E_RENDER}" \
  KATA_DEPLOY_MANIFEST="${KATA_DEPLOY_RENDER}" E2E_KATA_MANIFEST="${E2E_KATA_RENDER}" \
  "${ROOT}/hack/update-deploy-manifests.sh"

status=0
if ! diff -u "${ROOT}/deploy.yml" "${DEPLOY_RENDER}"; then
  status=1
fi
if ! diff -u "${ROOT}/e2e/multi-network-policy-nftables-e2e.yml" "${E2E_RENDER}"; then
  status=1
fi
if ! diff -u "${ROOT}/deploy-kata.yml" "${KATA_DEPLOY_RENDER}"; then
  status=1
fi
if ! diff -u "${ROOT}/e2e/multi-network-policy-nftables-e2e-kata.yml" "${E2E_KATA_RENDER}"; then
  status=1
fi

if [ "${status}" -ne 0 ]; then
  echo "generated manifests are stale; run hack/update-deploy-manifests.sh" >&2
fi

exit "${status}"
