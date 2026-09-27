#!/usr/bin/env bats

# The multinetworkpolicy.io/backend annotation selects a pod's backend
# regardless of its RuntimeClass, and can be changed on a running pod.

ns=test-kata-backend

setup_file() {
	cd $BATS_TEST_DIRNAME
	load "../../tests/common"
	load "kata"
	export MANIFEST_FILE="backend-annotation.yml"
	ensure_daemonset_running
	kubectl apply --wait --timeout=${kubewait_timeout} -f "${MANIFEST_FILE}"
	kubectl -n test-kata-backend wait --for=condition=ready -l app=test-kata-backend pod --timeout=${kubewait_timeout}
	wait_for_tcx_pinned test-kata-backend pod-runc-server net1
}

setup() {
	cd $BATS_TEST_DIRNAME
	load "../../tests/common"
	load "kata"
	runc_server=$(wait_for_net1_ip $ns pod-runc-server)
	kata_server=$(wait_for_net1_ip $ns pod-kata-server)
}

teardown_file() {
	cd $BATS_TEST_DIRNAME
	load "../../tests/common"
	teardown_file_common
}

# nft_tables <pod>: the number of the daemon's nftables tables in a runc pod.
nft_tables() {
	kubectl -n $ns exec "$1" -- sh -c "nft list tables | grep -c multi-networkpolicy || true"
}

set_backend() {
	kubectl -n $ns annotate pod "$1" --overwrite "multinetworkpolicy.io/backend=$2"
}

@test "runc pod with backend=tcx is policed by TCX, without nftables rules" {
	run tcx_pinned $ns pod-runc-server net1
	[ "$status" -eq 0 ]
	run nft_tables pod-runc-server
	[ "$output" = "0" ]
	run retry_until_success 10 nc_ok $ns pod-client-a ${runc_server} 5555
	[ "$status" -eq 0 ]
	run retry_until_deny 30 nc_ok $ns pod-client-b ${runc_server} 5555
	[ "$status" -eq 0 ]
}

@test "Kata pod with backend=nftables gets no TCX programs" {
	run kata_guest_kernel $ns pod-kata-server
	[ "$status" -eq 0 ]
	run tcx_pinned $ns pod-kata-server net1
	[ "$status" -ne 0 ]
	# This is why Kata pods need TCX: the tc redirect bypasses the nftables
	# rules, so the policy has no effect.
	run nc_ok $ns pod-client-b ${kata_server} 5555
	[ "$status" -eq 0 ]
}

@test "switching a running pod from tcx to nftables and back" {
	set_backend pod-runc-server nftables
	run wait_for_tcx_absent $ns pod-runc-server net1
	[ "$status" -eq 0 ]
	run wait_for_nft_rules $ns pod-runc-server test-kata-backend-ingress
	[ "$status" -eq 0 ]
	run retry_until_deny 30 nc_ok $ns pod-client-b ${runc_server} 5555
	[ "$status" -eq 0 ]

	set_backend pod-runc-server tcx
	run wait_for_tcx_pinned $ns pod-runc-server net1
	[ "$status" -eq 0 ]
	# the nftables rules are removed so they cannot enforce a stale policy
	run retry_until_success 30 sh -c "[ \"\$(kubectl -n $ns exec pod-runc-server -- sh -c 'nft list tables | grep -c multi-networkpolicy || true')\" = 0 ]"
	[ "$status" -eq 0 ]
	run retry_until_deny 30 nc_ok $ns pod-client-b ${runc_server} 5555
	[ "$status" -eq 0 ]
	run retry_until_success 10 nc_ok $ns pod-client-a ${runc_server} 5555
	[ "$status" -eq 0 ]
}
