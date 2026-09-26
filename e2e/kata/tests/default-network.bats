#!/usr/bin/env bats

# Kata pods ("tcfilter" networking) whose primary network is a net-attach-def
# (Multus default-network annotation): the policy applies to eth0.

setup_file() {
	cd $BATS_TEST_DIRNAME
	load "../../tests/common"
	load "kata"
	export MANIFEST_FILE="default-network.yml"
	ensure_daemonset_running
	kubectl apply --wait --timeout=${kubewait_timeout} -f "${MANIFEST_FILE}"
	kubectl -n test-kata-defnet wait --for=condition=ready -l app=test-kata-defnet pod --timeout=${kubewait_timeout}
	wait_for_tcx_pinned test-kata-defnet pod-server eth0
}

setup() {
	cd $BATS_TEST_DIRNAME
	load "../../tests/common"
	load "kata"
}

teardown_file() {
	cd $BATS_TEST_DIRNAME
	load "../../tests/common"
	teardown_file_common
}

@test "pod-server runs in a Kata VM with its primary interface behind a TC redirect" {
	run kata_guest_kernel test-kata-defnet pod-server
	[ "$status" -eq 0 ]
	run pod_netns_exec test-kata-defnet pod-server tc filter show dev eth0 ingress
	[ "$status" -eq 0 ]
	[[ "$output" == *"mirred"* ]]
}

@test "TCX programs are pinned for eth0" {
	run tcx_pinned test-kata-defnet pod-server eth0
	[ "$status" -eq 0 ]
}

@test "client-a (runc) -> server on the default network is allowed" {
	run retry_until_allow 30 nc_ok test-kata-defnet pod-client-a 2.2.43.1 5555
	[ "$status" -eq 0 ]
}

@test "client-b (Kata) -> server on the default network is denied" {
	run retry_until_deny 30 nc_ok test-kata-defnet pod-client-b 2.2.43.1 5555
	[ "$status" -eq 0 ]
}

@test "server -> clients on the default network is allowed (egress not isolated)" {
	run nc_ok test-kata-defnet pod-server 2.2.43.11 5555
	[ "$status" -eq 0 ]
	run nc_ok test-kata-defnet pod-server 2.2.43.12 5555
	[ "$status" -eq 0 ]
}
