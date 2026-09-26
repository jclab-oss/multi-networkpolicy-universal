#!/usr/bin/env bats

# Ingress policy on a Kata pod with "macvtap" networking. The daemon polices
# the macvtap device: for a macvlan net-attach-def, the VM's traffic never
# passes net1.

setup_file() {
	cd $BATS_TEST_DIRNAME
	load "../../tests/common"
	load "kata"
	if ! macvtap_supported; then
		skip "the kind nodes need devtmpfs on /dev (setup_cluster.sh with KATA_E2E_HOST_DEVTMPFS=1)"
	fi
	export MANIFEST_FILE="macvtap-ingress.yml"
	ensure_daemonset_running
	kubectl apply --wait --timeout=${kubewait_timeout} -f "${MANIFEST_FILE}"
	kubectl -n test-kata-macvtap wait --for=condition=ready -l app=test-kata-macvtap pod --timeout=${kubewait_timeout}
	wait_for_tcx_pinned test-kata-macvtap pod-server net1
}

setup() {
	cd $BATS_TEST_DIRNAME
	load "../../tests/common"
	load "kata"
	server_net1=$(wait_for_net1_ip "test-kata-macvtap" "pod-server")
}

teardown_file() {
	cd $BATS_TEST_DIRNAME
	load "../../tests/common"
	teardown_file_common
}

@test "pod-server runs in a Kata VM attached through macvtap" {
	run kata_guest_kernel test-kata-macvtap pod-server
	[ "$status" -eq 0 ]
	run pod_netns_exec test-kata-macvtap pod-server ip -d link show
	[ "$status" -eq 0 ]
	[[ "$output" == *"macvtap"* ]]
}

@test "the programs sit on the macvtap device, not on net1" {
	uid=$(pod_uid test-kata-macvtap pod-server)
	node=$(pod_node test-kata-macvtap pod-server)
	daemon=$(kubectl -n kube-system get pod -l name=multi-networkpolicy --field-selector spec.nodeName="$node" -o name)
	run sh -c "kubectl -n kube-system logs $daemon | grep 'pod $uid interface net1 is policed on tap.*_kata'"
	[ "$status" -eq 0 ]
}

@test "client-a -> server:5555 is allowed" {
	run retry_until_success 10 nc_ok test-kata-macvtap pod-client-a ${server_net1} 5555
	[ "$status" -eq 0 ]
}

@test "client-a -> server:6666 is denied (port not in policy)" {
	run retry_until_deny 30 nc_ok test-kata-macvtap pod-client-a ${server_net1} 6666
	[ "$status" -eq 0 ]
}

@test "client-b -> server:5555 is denied (peer not in policy)" {
	run retry_until_deny 30 nc_ok test-kata-macvtap pod-client-b ${server_net1} 5555
	[ "$status" -eq 0 ]
}
