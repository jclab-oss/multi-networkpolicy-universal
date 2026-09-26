#!/bin/sh
# Creates a kind cluster that runs Kata Containers and multi-networkpolicy
# with the TCX datapath enabled. Kata needs /dev/kvm on the host; kind nodes
# are privileged containers and see it.
set -o errexit

E2E_KATA="$(cd "$(dirname "$0")" && pwd -P)"
cd "${E2E_KATA}/.."
export PATH=./bin:${PATH}

OCI_BIN="${OCI_BIN:-docker}"
CLUSTER="${KATA_CLUSTER_NAME:-kata}"
KATA_DEPLOY_VERSION="${KATA_DEPLOY_VERSION:-4.2.0}"
# Keep the cluster out of the user's kubeconfig; run_tests.sh uses this file.
KUBECONFIG="${KATA_KUBECONFIG:-${E2E_KATA}/kubeconfig}"
export KUBECONFIG

if [ ! -c /dev/kvm ]; then
	echo "/dev/kvm is required to run Kata Containers" >&2
	exit 1
fi

$OCI_BIN build -t localhost:5000/multi-networkpolicy-nftables:e2e -f ../Dockerfile ..
$OCI_BIN build -t localhost:5000/multi-networkpolicy-nftables:e2e-test -f Dockerfile .
$OCI_BIN build -t localhost:5000/install-cni:e2e -f cni.Dockerfile .

cat <<KIND | kind create cluster --name "${CLUSTER}" --kubeconfig "${KUBECONFIG}" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
KIND

for image in multi-networkpolicy-nftables:e2e multi-networkpolicy-nftables:e2e-test install-cni:e2e; do
	kind load docker-image --name "${CLUSTER}" "localhost:5000/${image}"
done
kind export kubeconfig --name "${CLUSTER}" --kubeconfig "${KUBECONFIG}"

# The TCX datapath pins its programs in bpffs; systemd mounts it on regular
# hosts, kind nodes do not.
# Kata backs the VM memory with a file in /dev/shm, which the container
# runtime limits to 64 MiB on kind nodes; the size is only an upper bound.
for node in $(kind get nodes --name "${CLUSTER}"); do
	$OCI_BIN exec "${node}" sh -c 'mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf'
	$OCI_BIN exec "${node}" mount -o remount,size=50% /dev/shm
	# runtime-rs creates the sandbox cgroup through systemd's D-Bus API,
	# which the kind node image does not ship.
	$OCI_BIN exec "${node}" sh -c 'command -v dbus-daemon >/dev/null ||
		{ apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dbus; }'
	$OCI_BIN exec "${node}" systemctl start dbus.socket dbus.service
done

# Kata's "macvtap" networking opens the /dev/tap<ifindex> device the kernel
# creates for a new macvtap interface. A kind node's /dev is a static copy,
# so the macvtap suite needs the kernel's devtmpfs mounted over it. devtmpfs
# is a single instance shared with the host, which is fine on a throwaway CI
# runner; opt in with KATA_E2E_HOST_DEVTMPFS=1. The macvtap tests are
# skipped otherwise.
if [ "${KATA_E2E_HOST_DEVTMPFS:-0}" = 1 ]; then
	for node in $(kind get nodes --name "${CLUSTER}"); do
		$OCI_BIN exec "${node}" sh -c '
			set -e
			[ "$(awk '"'"'$2 == "/dev" { t = $3 } END { print t }'"'"' /proc/mounts)" = devtmpfs ] && exit 0
			mount -t devtmpfs devtmpfs /dev
			mount -t devpts -o newinstance,ptmxmode=0666,mode=0620,gid=5 devpts /dev/pts
			mount -t tmpfs -o size=50% shm /dev/shm
			mkdir -p /dev/mqueue && mount -t mqueue mqueue /dev/mqueue'
	done
fi

kubectl apply --wait --timeout=10s -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.1/manifests/calico.yaml
kubectl -n kube-system set env daemonset/calico-node FELIX_IGNORELOOSERPF=true FELIX_XDPENABLED=false
kubectl -n kube-system rollout status daemonset/calico-node --timeout=300s
kubectl -n kube-system wait --for=condition=available deploy/coredns --timeout=300s

kubectl apply --wait --timeout=10s -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/master/deployments/multus-daemonset.yml
kubectl -n kube-system wait --for=condition=ready -l name=multus pod --timeout=660s
kubectl apply --wait --timeout=10s -f cni-install.yml
kubectl -n kube-system rollout status daemonset/install-cni-plugins --timeout=300s

helm install kata-deploy oci://ghcr.io/kata-containers/kata-deploy-charts/kata-deploy \
	--version "${KATA_DEPLOY_VERSION}" --namespace kube-system \
	--values "${E2E_KATA}/kata-deploy.values.yaml" --wait --timeout 15m
for rc in kata-qemu kata-qemu-runtime-rs kata-qemu-macvtap; do
	kubectl wait --for=create "runtimeclass/${rc}" --timeout=300s
done

kubectl apply --wait --timeout=10s -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multi-networkpolicy/master/scheme.yml

kubectl apply --wait --timeout=10s -f multi-network-policy-nftables-e2e-kata.yml
kubectl -n kube-system rollout status daemonset/multi-networkpolicy-ds-amd64 --timeout=300s
kubectl -n kube-system wait --for=condition=ready -l name=multi-networkpolicy pod --timeout=300s

echo "kind cluster ${CLUSTER} with Kata Containers and multi-networkpolicy is ready"
