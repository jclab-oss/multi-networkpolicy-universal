#!/usr/bin/env bats

# Egress policy with a port on a Kata pod of the Rust runtime (runtime-rs),
# whose "tcfilter" networking is implemented separately from the Go runtime's.

setup_file() {
	cd $BATS_TEST_DIRNAME
	load "../../tests/common"
	load "kata"
	export MANIFEST_FILE="runtime-rs-egress.yml"
	ensure_daemonset_running
	kubectl apply --wait --timeout=${kubewait_timeout} -f "${MANIFEST_FILE}"
	kubectl -n test-kata-rs wait --for=condition=ready -l app=test-kata-rs pod --timeout=${kubewait_timeout}
	wait_for_tcx_pinned test-kata-rs pod-a net1
}

setup() {
	cd $BATS_TEST_DIRNAME
	load "../../tests/common"
	load "kata"
	a_net1=$(wait_for_net1_ip "test-kata-rs" "pod-a")
	b_net1=$(wait_for_net1_ip "test-kata-rs" "pod-b")
	c_net1=$(wait_for_net1_ip "test-kata-rs" "pod-c")
}

teardown_file() {
	cd $BATS_TEST_DIRNAME
	load "../../tests/common"
	teardown_file_common
}

@test "pod-a runs in a Kata VM of the Rust runtime behind a TC redirect" {
	run kata_guest_kernel test-kata-rs pod-a
	[ "$status" -eq 0 ]
	run pod_netns_exec test-kata-rs pod-a tc filter show dev net1 ingress
	[ "$status" -eq 0 ]
	[[ "$output" == *"mirred"* ]]
}

@test "pod-a -> pod-b:5555 is allowed" {
	run retry_until_success 10 nc_ok test-kata-rs pod-a ${b_net1} 5555
	[ "$status" -eq 0 ]
}

@test "pod-a -> pod-b:6666 is denied (port not in policy)" {
	run retry_until_deny 30 nc_ok test-kata-rs pod-a ${b_net1} 6666
	[ "$status" -eq 0 ]
}

@test "pod-a -> pod-c:5555 is denied (peer not in policy)" {
	run retry_until_deny 30 nc_ok test-kata-rs pod-a ${c_net1} 5555
	[ "$status" -eq 0 ]
}

@test "pod-c -> pod-a is allowed (ingress not isolated), replies pass isolated egress" {
	run nc_ok test-kata-rs pod-c ${a_net1} 5555
	[ "$status" -eq 0 ]
}
