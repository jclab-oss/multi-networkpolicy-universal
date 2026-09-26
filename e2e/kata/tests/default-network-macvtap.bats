#!/usr/bin/env bats

# Kata pods with "macvtap" networking whose primary network is a macvlan
# net-attach-def (Multus default-network annotation): the VM's traffic passes
# the macvtap device Kata stacks on eth0's lower device, never eth0 itself.

setup_file() {
	cd $BATS_TEST_DIRNAME
	load "../../tests/common"
	load "kata"
	if ! macvtap_supported; then
		skip "the kind nodes need devtmpfs on /dev (setup_cluster.sh with KATA_E2E_HOST_DEVTMPFS=1)"
	fi
	export MANIFEST_FILE="default-network-macvtap.yml"
	ensure_daemonset_running
	kubectl apply --wait --timeout=${kubewait_timeout} -f "${MANIFEST_FILE}"
	kubectl -n test-kata-defnet-macvtap wait --for=condition=ready -l app=test-kata-defnet-macvtap pod --timeout=${kubewait_timeout}
	wait_for_tcx_pinned test-kata-defnet-macvtap pod-server eth0
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

@test "eth0 of pod-server is policed on its macvtap device" {
	run kata_guest_kernel test-kata-defnet-macvtap pod-server
	[ "$status" -eq 0 ]
	uid=$(pod_uid test-kata-defnet-macvtap pod-server)
	node=$(pod_node test-kata-defnet-macvtap pod-server)
	daemon=$(kubectl -n kube-system get pod -l name=multi-networkpolicy --field-selector spec.nodeName="$node" -o name)
	run sh -c "kubectl -n kube-system logs $daemon | grep 'pod $uid interface eth0 is policed on tap.*_kata'"
	[ "$status" -eq 0 ]
}

@test "client-a (runc) -> server on the default network is allowed" {
	run retry_until_allow 30 nc_ok test-kata-defnet-macvtap pod-client-a 2.2.44.1 5555
	[ "$status" -eq 0 ]
}

@test "client-b (Kata) -> server on the default network is denied" {
	run retry_until_deny 30 nc_ok test-kata-defnet-macvtap pod-client-b 2.2.44.1 5555
	[ "$status" -eq 0 ]
}
