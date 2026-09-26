# Helpers for the Kata Containers suite. Loaded after ../../tests/common.bash.

pin_root=/sys/fs/bpf/multi-networkpolicy/endpoints

pod_node() {
	kubectl -n "$1" get pod "$2" -o jsonpath='{.spec.nodeName}'
}

pod_uid() {
	kubectl -n "$1" get pod "$2" -o jsonpath='{.metadata.uid}'
}

# tcx_pinned <ns> <pod> <iface>: succeeds when the TCX programs of the pod's
# interface are pinned on its node.
tcx_pinned() {
	local node uid
	node=$(pod_node "$1" "$2")
	uid=$(pod_uid "$1" "$2")
	docker exec "$node" test -e "${pin_root}/${uid}/$3/ingress" &&
		docker exec "$node" test -e "${pin_root}/${uid}/$3/egress"
}

wait_for_tcx_pinned() {
	local attempts=0
	while [ $attempts -lt "${4:-60}" ]; do
		tcx_pinned "$1" "$2" "$3" && return 0
		sleep 1
		attempts=$((attempts + 1))
	done
	return 1
}

wait_for_tcx_absent() {
	local attempts=0
	while [ $attempts -lt "${4:-90}" ]; do
		tcx_pinned "$1" "$2" "$3" || return 0
		sleep 1
		attempts=$((attempts + 1))
	done
	return 1
}

# pod_netns_exec <ns> <pod> <command...>: runs a command in the pod's network
# namespace on the node, i.e. on the host side of the Kata VM.
pod_netns_exec() {
	local ns="$1" pod="$2" node sandbox netns
	shift 2
	node=$(pod_node "$ns" "$pod")
	sandbox=$(docker exec "$node" crictl pods --namespace "$ns" --name "^${pod}\$" --state ready -q | head -1)
	netns=$(docker exec "$node" crictl inspectp "$sandbox" | grep -o '"path": *"/var/run/netns/[^"]*"' | head -1 | sed 's/.*"\(\/var\/run\/netns\/[^"]*\)"/\1/')
	docker exec "$node" nsenter --net="$netns" "$@"
}

# kata_guest_kernel <ns> <pod>: fails unless the pod runs in a VM, i.e. its
# kernel differs from the node's.
kata_guest_kernel() {
	local node guest host
	node=$(pod_node "$1" "$2")
	guest=$(kubectl -n "$1" exec "$2" -- uname -r)
	host=$(docker exec "$node" uname -r)
	[ -n "$guest" ] && [ "$guest" != "$host" ]
}

nc_ok() {
	kubectl -n "$1" exec "$2" -- sh -c "echo x | nc -w 1 $3 $4"
}

# disable_daemon/enable_daemon stop and restart the DaemonSet gracefully,
# which removes the policies it applied.
disable_daemon() {
	kubectl -n kube-system patch daemonsets multi-networkpolicy-ds-amd64 -p '{"spec": {"template": {"spec": {"nodeSelector": {"non-existing": "true"}}}}}'
	kubectl -n kube-system wait --for=delete -l app=multi-networkpolicy pod --timeout=${kubewait_timeout}
}

enable_daemon() {
	kubectl -n kube-system patch daemonsets multi-networkpolicy-ds-amd64 --type json -p='[{"op": "remove", "path": "/spec/template/spec/nodeSelector/non-existing"}]'
	kubectl -n kube-system rollout status daemonset/multi-networkpolicy-ds-amd64 --timeout=${kubewait_timeout}
	kubectl -n kube-system wait --for=condition=ready -l app=multi-networkpolicy pod --timeout=${kubewait_timeout}
}

# macvtap_supported: Kata's macvtap networking needs the kernel-created
# /dev/tap* devices, i.e. devtmpfs on the nodes' /dev.
macvtap_supported() {
	local node
	for node in $(kubectl get nodes -o jsonpath='{.items[*].metadata.name}'); do
		# statfs reports tmpfs for devtmpfs; the last /dev mount is on top.
		[ "$(docker exec "$node" awk '$2 == "/dev" { t = $3 } END { print t }' /proc/mounts)" = devtmpfs ] || return 1
	done
}
