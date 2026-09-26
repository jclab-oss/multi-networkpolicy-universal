#!/usr/bin/env bats

# Ingress policy on a Kata pod with the default "tcfilter" networking: the
# daemon must enforce it through TCX, since the TC redirect bypasses nftables.

setup_file() {
	cd $BATS_TEST_DIRNAME
	load "../../tests/common"
	load "kata"
	export MANIFEST_FILE="tcfilter-ingress.yml"
	ensure_daemonset_running
	kubectl apply --wait --timeout=${kubewait_timeout} -f "${MANIFEST_FILE}"
	kubectl -n test-kata-tcfilter wait --for=condition=ready -l app=test-kata-tcfilter pod --timeout=${kubewait_timeout}
	wait_for_tcx_pinned test-kata-tcfilter pod-server net1
}

setup() {
	cd $BATS_TEST_DIRNAME
	load "../../tests/common"
	load "kata"
	server_net1=$(wait_for_net1_ip "test-kata-tcfilter" "pod-server")
	client_a_net1=$(wait_for_net1_ip "test-kata-tcfilter" "pod-client-a")
	client_b_net1=$(wait_for_net1_ip "test-kata-tcfilter" "pod-client-b")
	server_net1_6=$(wait_for_net1_ip6 "test-kata-tcfilter" "pod-server")
}

teardown_file() {
	cd $BATS_TEST_DIRNAME
	load "../../tests/common"
	teardown_file_common
}

@test "pod-server runs in a Kata VM behind a TC redirect" {
	run kata_guest_kernel test-kata-tcfilter pod-server
	[ "$status" -eq 0 ]
	run pod_netns_exec test-kata-tcfilter pod-server tc filter show dev net1 ingress
	[ "$status" -eq 0 ]
	[[ "$output" == *"mirred"* ]]
}

@test "TCX programs are pinned for the Kata pods only" {
	run tcx_pinned test-kata-tcfilter pod-server net1
	[ "$status" -eq 0 ]
	run wait_for_tcx_pinned test-kata-tcfilter pod-client-a net1
	[ "$status" -eq 0 ]
	run tcx_pinned test-kata-tcfilter pod-client-b net1
	[ "$status" -ne 0 ]
}

@test "client-a -> server is allowed" {
	run retry_until_success 10 nc_ok test-kata-tcfilter pod-client-a ${server_net1} 5555
	[ "$status" -eq 0 ]
}

@test "client-b -> server is denied" {
	run retry_until_deny 30 nc_ok test-kata-tcfilter pod-client-b ${server_net1} 5555
	[ "$status" -eq 0 ]
}

@test "client-a -> server is allowed over IPv6" {
	run retry_until_success 10 nc_ok test-kata-tcfilter pod-client-a ${server_net1_6} 5555
	[ "$status" -eq 0 ]
}

@test "client-b -> server is denied over IPv6" {
	run retry_until_deny 30 nc_ok test-kata-tcfilter pod-client-b ${server_net1_6} 5555
	[ "$status" -eq 0 ]
}

@test "server -> clients is allowed (egress not isolated)" {
	run nc_ok test-kata-tcfilter pod-server ${client_a_net1} 5555
	[ "$status" -eq 0 ]
	run nc_ok test-kata-tcfilter pod-server ${client_b_net1} 5555
	[ "$status" -eq 0 ]
}

@test "stopping the daemon removes the programs, restarting restores them" {
	ensure_daemonset_running
	disable_daemon
	run wait_for_tcx_absent test-kata-tcfilter pod-server net1
	[ "$status" -eq 0 ]
	run retry_until_allow 30 nc_ok test-kata-tcfilter pod-client-b ${server_net1} 5555
	[ "$status" -eq 0 ]

	enable_daemon
	run wait_for_tcx_pinned test-kata-tcfilter pod-server net1
	[ "$status" -eq 0 ]
	run retry_until_deny 30 nc_ok test-kata-tcfilter pod-client-b ${server_net1} 5555
	[ "$status" -eq 0 ]
}

@test "the policy stays enforced while the daemon is killed" {
	ensure_daemonset_running
	node=$(pod_node test-kata-tcfilter pod-server)
	docker exec "$node" pkill -KILL -f /usr/bin/multi-networkpolicy-nftables
	# No graceful shutdown ran: the pinned programs are still attached.
	run tcx_pinned test-kata-tcfilter pod-server net1
	[ "$status" -eq 0 ]
	run nc_ok test-kata-tcfilter pod-client-b ${server_net1} 5555
	[ "$status" -ne 0 ]
	run nc_ok test-kata-tcfilter pod-client-a ${server_net1} 5555
	[ "$status" -eq 0 ]
	ensure_daemonset_running
}
