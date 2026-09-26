#!/bin/bash
# Runs the Kata Containers e2e suite against the cluster from setup_cluster.sh.
E2E_KATA="$(dirname "$(realpath "$0")")"
cd "${E2E_KATA}/.." || exit 1
export PATH="${PWD}/bin:${PATH}"
CLUSTER="${KATA_CLUSTER_NAME:-kata}"
KUBECONFIG="${KATA_KUBECONFIG:-${E2E_KATA}/kubeconfig}"
export KUBECONFIG

mkdir -p ./artifacts/junit
suite_failed=0
for f in "${E2E_KATA}"/tests/*.bats; do
	name="kata-$(basename "$f" .bats)"
	echo "=== Running: ${name} ==="
	if bats --help 2>&1 | grep -q -- "--report-formatter"; then
		BATS_REPORT_FILENAME="${name}.xml" bats --report-formatter junit --output ./artifacts/junit "$f"
	else
		bats "$f"
	fi
	if [ $? -ne 0 ]; then
		suite_failed=1
		kind export logs --name "${CLUSTER}" "./artifacts/${name}.test/kind-logs" || true
	fi
done
exit $suite_failed
