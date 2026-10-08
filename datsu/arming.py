"""How to ARM each condition on a disposable lab, so `datsu validate` can exercise the detector.

This is the only module that *creates* conditions. It is used exclusively by `datsu validate`,
which gates itself behind an explicit marker and is meant for an isolated, disposable lab — never
a production or shared host. Each entry gives the human-readable preconditions, a command that
arms the condition and leaves it in place, and a cleanup command that removes it.

Version/CVE scenarios and a few host-state ones are intentionally NOT armed here (you cannot
install a vulnerable runc or flip the host cgroup mode on demand); `datsu validate` reports those
as detector-validated against the node's ambient state, which is the honest outcome.

Author: d3vn0mi (RavenSec)
"""
from __future__ import annotations

NS = "datsu-arm"


def _dk(sid, flags, extra_arm=""):
    """Arm a docker container exhibiting `flags`; cleanup removes it."""
    name = f"datsu-arm-{sid.lower()}"
    arm = f"docker rm -f {name} >/dev/null 2>&1; docker run -d --name {name} {flags} alpine sleep 600 >/dev/null"
    if extra_arm:
        arm += "\n" + extra_arm.replace("<N>", name)
    return arm, f"docker rm -f {name} >/dev/null 2>&1"


def _rbac(sid, api_groups, resources, verbs):
    """Arm a non-system ServiceAccount bound to a Role granting verbs on resources (datsu-arm ns)."""
    sa = f"datsu-arm-{sid.lower()}-sa"
    role = f"datsu-arm-{sid.lower()}-role"
    ag = '","'.join(api_groups); rs = '","'.join(resources); vb = '","'.join(verbs)
    arm = (
        f'kubectl create ns {NS} >/dev/null 2>&1; '
        f'kubectl -n {NS} create sa {sa} --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1\n'
        f'cat <<EOF | kubectl apply -f - >/dev/null 2>&1\n'
        f'apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\n'
        f'metadata: {{name: {role}, namespace: {NS}}}\n'
        f'rules: [{{apiGroups: ["{ag}"], resources: ["{rs}"], verbs: ["{vb}"]}}]\nEOF\n'
        f'kubectl -n {NS} create rolebinding {role}-rb --role={role} --serviceaccount={NS}:{sa} '
        f'--dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1')
    return arm, f"kubectl delete ns {NS} --wait=false >/dev/null 2>&1"


def _pod(sid, overrides):
    """Arm a pod in datsu-arm ns from a JSON spec override; cleanup deletes the ns."""
    name = f"datsu-arm-{sid.lower()}"
    arm = (f'kubectl create ns {NS} >/dev/null 2>&1; '
           f"kubectl -n {NS} run {name} --image=alpine --restart=Never --overrides='{overrides}' "
           f"--command -- sleep 600 >/dev/null 2>&1")
    return arm, f"kubectl delete ns {NS} --wait=false >/dev/null 2>&1"


# id -> (preconditions, arm_sh, cleanup_sh)
METADATA: dict = {}

def _m(sid, pre, arm=None, cleanup=None):
    METADATA[sid] = {"pre": pre, "arm": arm, "cleanup": cleanup}

# ---- Docker: privileged / caps (generic docker-run arms) ----
_m("DK-01", "A container started with --privileged (all caps, no seccomp/apparmor, device access).",
   *_dk("DK-01", "--privileged"))
_m("DK-02", "A container with the Docker socket bind-mounted (-v /var/run/docker.sock).",
   *_dk("DK-02", "-v /var/run/docker.sock:/run/docker.sock"))
_m("DK-03", "A container with CAP_SYS_ADMIN (and, for the full breakout, a cgroup-v1 host + apparmor=unconfined).",
   *_dk("DK-03", "--cap-add=SYS_ADMIN --security-opt apparmor=unconfined"))
_m("DK-04", "A container granted CAP_SYS_MODULE.", *_dk("DK-04", "--cap-add=SYS_MODULE"))
_m("DK-05", "A container granted CAP_DAC_READ_SEARCH.", *_dk("DK-05", "--cap-add=DAC_READ_SEARCH"))
_m("DK-06", "A container with host PID namespace (--pid=host) and CAP_SYS_PTRACE.",
   *_dk("DK-06", "--pid=host --cap-add=SYS_PTRACE"))
_m("DK-07", "A container bind-mounting the host root filesystem (-v /:/host).", *_dk("DK-07", "-v /:/host"))
_m("DK-08", "A container with a raw host block device exposed (--device).",
   *_dk("DK-08", "--device=/dev/null"))  # /dev/null is a safe stand-in device for the detector
_m("DK-09", "A container sharing host network and IPC namespaces (--network=host --ipc=host).",
   *_dk("DK-09", "--network=host --ipc=host"))
_m("DK-10", "A container running with seccomp disabled (--security-opt seccomp=unconfined).",
   *_dk("DK-10", "--security-opt seccomp=unconfined"))
_m("DK-11", "A container with a setuid-root helper reachable by a non-root user (no-new-privs off).",
   f"docker rm -f datsu-arm-dk11 >/dev/null 2>&1; docker run -d --name datsu-arm-dk11 alpine sleep 600 >/dev/null; "
   f"docker exec datsu-arm-dk11 sh -c 'cp /bin/busybox /usr/local/bin/esc-helper && chmod 4755 /usr/local/bin/esc-helper'",
   "docker rm -f datsu-arm-dk11 >/dev/null 2>&1")
_m("DK-13", "A local user who is a member of the docker group.",
   "id -u datsu-arm-u >/dev/null 2>&1 || useradd -m -s /bin/sh datsu-arm-u 2>/dev/null; usermod -aG docker datsu-arm-u",
   "gpasswd -d datsu-arm-u docker >/dev/null 2>&1; userdel -r datsu-arm-u >/dev/null 2>&1")
_m("DK-14", "A container with an rshared bind-propagation mount.",
   *_dk("DK-14", "--mount type=bind,src=/tmp,dst=/mnt/datsu,bind-propagation=rshared"))
_m("DK-15", "A privileged container that rewrote the host core_pattern to a pipe handler.",
   "docker rm -f datsu-arm-dk15 >/dev/null 2>&1; docker run -d --name datsu-arm-dk15 --privileged alpine sleep 600 >/dev/null; "
   "docker exec datsu-arm-dk15 sh -c 'echo \"|/tmp/datsu-h %P\" > /proc/sys/kernel/core_pattern'",
   "docker rm -f datsu-arm-dk15 >/dev/null 2>&1; echo core > /proc/sys/kernel/core_pattern 2>/dev/null")
_m("DK-27", "A container granted CAP_BPF or CAP_PERFMON.", *_dk("DK-27", "--cap-add=BPF --cap-add=PERFMON"))
_m("DK-28", "A container granted CAP_SYS_RAWIO.", *_dk("DK-28", "--cap-add=SYS_RAWIO"))
_m("DK-29", "A container granted CAP_SYS_BOOT.", *_dk("DK-29", "--cap-add=SYS_BOOT"))
_m("DK-30", "A container granted CAP_NET_ADMIN.", *_dk("DK-30", "--cap-add=NET_ADMIN"))
_m("DK-31", "A container granted CAP_CHECKPOINT_RESTORE.", *_dk("DK-31", "--cap-add=CHECKPOINT_RESTORE"))
_m("DK-32", "A container with a writable host /sys (or /sys/fs/cgroup) bind-mount.",
   *_dk("DK-32", "-v /sys:/host-sys"))
_m("DK-33", "A container with a writable host /proc bind-mount (or masked-paths disabled).",
   *_dk("DK-33", "-v /proc:/host-proc"))
_m("DK-34", "A container with /dev/mem, /dev/kmem or /dev/port exposed.",
   *_dk("DK-34", "--device=/dev/mem"))
_m("DK-35", "A container with AppArmor disabled (apparmor=unconfined).",
   *_dk("DK-35", "--security-opt apparmor=unconfined"))
_m("DK-36", "A container with SELinux labelling disabled (label:disable) on an enforcing host.",
   *_dk("DK-36", "--security-opt label=disable"))
_m("DK-37", "A container with the containerd/buildkit socket bind-mounted.",
   *_dk("DK-37", "-v /run/containerd/containerd.sock:/run/containerd/containerd.sock"))
_m("DK-38", "A container bind-mounting host /lib/modules or /boot.", *_dk("DK-38", "-v /lib/modules:/lib/modules"))

# ---- Docker: version / host-state (not auto-armed) ----
for _v, _p in {
    "DK-12": "dockerd listening on an unauthenticated TCP socket (tcp/2375). (host daemon reconfigure — not auto-armed)",
    "DK-16": "runc version in the Leaky Vessels (CVE-2024-21626) vulnerable range.",
    "DK-17": "runc version in the 2025 maskedPaths/procfs race range.",
    "DK-18": "kernel version in the container-LPE vulnerable window.",
    "DK-19": "runc <= 1.0.0-rc6 / Docker < 18.09.2 (CVE-2019-5736).",
    "DK-20": "BuildKit < 0.12.5 / Docker < 24.0.9 or < 25.0.2 (Leaky Vessels).",
    "DK-21": "runc < 1.0.0-rc95 (CVE-2021-30465).",
    "DK-22": "containerd < 1.3.9/1.4.3 plus a host-netns container (CVE-2020-15257).",
    "DK-23": "Docker < 18.09.0 (CVE-2018-15664 docker cp).",
    "DK-24": "Docker == 19.03.0 (CVE-2019-14271 docker cp libnss).",
    "DK-25": "kernel < 5.17, cgroup v1 reachable, unprivileged userns enabled (CVE-2022-0492).",
    "DK-26": "Docker with an AuthZ plugin configured and engine < 23.0.14/27.1.1 (CVE-2024-41110).",
}.items():
    _m(_v, _p)

# ---- Kubernetes: pods / posture ----
_m("K8-02", "A privileged pod (securityContext.privileged=true).",
   *_pod("K8-02", '{"spec":{"containers":[{"name":"c","image":"alpine","command":["sleep","600"],"securityContext":{"privileged":true}}]}}'))
_m("K8-03", "A pod with a hostPath volume mounting the node root (/).",
   *_pod("K8-03", '{"spec":{"containers":[{"name":"c","image":"alpine","command":["sleep","600"],"volumeMounts":[{"name":"h","mountPath":"/host"}]}],"volumes":[{"name":"h","hostPath":{"path":"/"}}]}}'))
_m("K8-04", "A pod sharing host PID/Network/IPC namespaces.",
   *_pod("K8-04", '{"spec":{"hostPID":true,"hostNetwork":true,"hostIPC":true,"containers":[{"name":"c","image":"alpine","command":["sleep","600"]}]}}'))
_m("K8-07", "A namespace without Pod Security 'restricted' enforcement.",
   f'kubectl create ns {NS} >/dev/null 2>&1', f"kubectl delete ns {NS} --wait=false >/dev/null 2>&1")
_m("K8-08", "Two running pods retaining NET_RAW on a shared pod network.",
   f'kubectl create ns {NS} >/dev/null 2>&1; kubectl -n {NS} run datsu-arm-k808 --image=alpine --restart=Never --command -- sleep 600 >/dev/null 2>&1',
   f"kubectl delete ns {NS} --wait=false >/dev/null 2>&1")
_m("K8-09", "A Secret stored in the node's embedded etcd (on-disk db root-readable).",
   f'kubectl create ns {NS} >/dev/null 2>&1; kubectl -n {NS} create secret generic datsu-arm-k809 --from-literal=x=y >/dev/null 2>&1',
   f"kubectl delete ns {NS} --wait=false >/dev/null 2>&1")
_m("K8-10", "The k3s server manifests directory left world/group-writable.",
   'd=/var/lib/rancher/k3s/server/manifests; [ -d "$d" ] && { stat -c "%a" "$d" > /tmp/.datsu-k810; chmod 777 "$d"; }',
   'd=/var/lib/rancher/k3s/server/manifests; [ -f /tmp/.datsu-k810 ] && chmod "$(cat /tmp/.datsu-k810)" "$d" 2>/dev/null; rm -f /tmp/.datsu-k810')
_m("K8-13", "A ClusterRoleBinding granting system:anonymous a ClusterRole.",
   'kubectl create clusterrolebinding datsu-arm-k813 --clusterrole=view --user=system:anonymous --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1',
   'kubectl delete clusterrolebinding datsu-arm-k813 --wait=false >/dev/null 2>&1')
_m("K8-16", "A ClusterRole granting escalate/bind on roles.",
   'cat <<EOF | kubectl apply -f - >/dev/null 2>&1\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata: {name: datsu-arm-k816}\nrules: [{apiGroups: ["rbac.authorization.k8s.io"], resources: ["clusterroles"], verbs: ["escalate","bind"]}]\nEOF',
   'kubectl delete clusterrole datsu-arm-k816 --wait=false >/dev/null 2>&1')
_m("K8-34", "A pod hostPath-mounting a sensitive node path (container socket / kubelet / pki / proc).",
   *_pod("K8-34", '{"spec":{"containers":[{"name":"c","image":"alpine","command":["sleep","600"],"volumeMounts":[{"name":"h","mountPath":"/host"}]}],"volumes":[{"name":"h","hostPath":{"path":"/var/lib/kubelet"}}]}}'))
_m("K8-36", "A pod adding a dangerous Linux capability via securityContext.capabilities.add.",
   *_pod("K8-36", '{"spec":{"containers":[{"name":"c","image":"alpine","command":["sleep","600"],"securityContext":{"capabilities":{"add":["SYS_ADMIN"]}}}]}}'))
_m("K8-37", "A legacy long-lived ServiceAccount-token Secret.",
   f'kubectl create ns {NS} >/dev/null 2>&1; kubectl -n {NS} create sa datsu-arm-sa837 --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1; '
   f'cat <<EOF | kubectl apply -f - >/dev/null 2>&1\napiVersion: v1\nkind: Secret\nmetadata: {{name: datsu-arm-k837, namespace: {NS}, annotations: {{kubernetes.io/service-account.name: datsu-arm-sa837}}}}\ntype: kubernetes.io/service-account-token\nEOF',
   f"kubectl delete ns {NS} --wait=false >/dev/null 2>&1")
_m("K8-39", "A pod on a non-default ServiceAccount with the token auto-mounted.",
   f'kubectl create ns {NS} >/dev/null 2>&1; kubectl -n {NS} create sa datsu-arm-sa839 --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1; '
   f'kubectl -n {NS} run datsu-arm-k839 --image=alpine --restart=Never --overrides=\'{{"spec":{{"serviceAccountName":"datsu-arm-sa839"}}}}\' --command -- sleep 600 >/dev/null 2>&1',
   f"kubectl delete ns {NS} --wait=false >/dev/null 2>&1")
_m("K8-41", "A pod with shareProcessNamespace: true.",
   *_pod("K8-41", '{"spec":{"shareProcessNamespace":true,"containers":[{"name":"c","image":"alpine","command":["sleep","600"]}]}}'))
_m("K8-42", "A pod running as root (no runAsNonRoot).",
   *_pod("K8-42", '{"spec":{"containers":[{"name":"c","image":"alpine","command":["sleep","600"]}]}}'))
_m("K8-43", "A pod binding a hostPort.",
   *_pod("K8-43", '{"spec":{"containers":[{"name":"c","image":"alpine","command":["sleep","600"],"ports":[{"containerPort":9999,"hostPort":39999}]}]}}'))
_m("K8-45", "A pod using a (deprecated) gitRepo volume.",
   *_pod("K8-45", '{"spec":{"containers":[{"name":"c","image":"alpine","command":["sleep","600"],"volumeMounts":[{"name":"g","mountPath":"/repo"}]}],"volumes":[{"name":"g","gitRepo":{"repository":"https://example.com/x.git"}}]}}'))
_m("K8-53", "A pod running an unpinned :latest image.",
   f'kubectl create ns {NS} >/dev/null 2>&1; kubectl -n {NS} run datsu-arm-k853 --image=alpine:latest --restart=Never --command -- sleep 600 >/dev/null 2>&1',
   f"kubectl delete ns {NS} --wait=false >/dev/null 2>&1")

# ---- Kubernetes RBAC (generic) ----
_m("K8-01", "A non-system ServiceAccount bound to a Role granting create on pods.", *_rbac("K8-01", [""], ["pods"], ["create"]))
_m("K8-05", "A privileged DaemonSet.",
   'cat <<EOF | kubectl apply -f - >/dev/null 2>&1\napiVersion: apps/v1\nkind: DaemonSet\nmetadata: {name: datsu-arm-k805, namespace: kube-system}\nspec: {selector: {matchLabels: {app: datsu-arm-k805}}, template: {metadata: {labels: {app: datsu-arm-k805}}, spec: {containers: [{name: c, image: alpine, command: ["sleep","600"], securityContext: {privileged: true}}]}}}\nEOF',
   'kubectl -n kube-system delete ds datsu-arm-k805 --wait=false >/dev/null 2>&1')
_m("K8-14", "A non-system ServiceAccount that can create PersistentVolumes.", *_rbac("K8-14", [""], ["persistentvolumes"], ["create"]))
_m("K8-15", "A non-system ServiceAccount that can create pods/ephemeralcontainers.", *_rbac("K8-15", [""], ["pods/ephemeralcontainers"], ["create"]))
_m("K8-19", "A non-system ServiceAccount that can create pods/exec.", *_rbac("K8-19", [""], ["pods/exec"], ["create"]))
_m("K8-20", "A non-system ServiceAccount that can create pods/attach.", *_rbac("K8-20", [""], ["pods/attach"], ["create"]))
_m("K8-21", "A non-system ServiceAccount that can get/list secrets cluster-wide.", *_rbac("K8-21", [""], ["secrets"], ["get", "list"]))
_m("K8-22", "A non-system ServiceAccount that can create serviceaccounts/token.", *_rbac("K8-22", [""], ["serviceaccounts/token"], ["create"]))
_m("K8-23", "A non-system ServiceAccount granted impersonate.", *_rbac("K8-23", [""], ["users", "groups", "serviceaccounts"], ["impersonate"]))
_m("K8-24", "A non-system ServiceAccount that can approve certificatesigningrequests.",
   *_rbac("K8-24", ["certificates.k8s.io"], ["certificatesigningrequests", "certificatesigningrequests/approval"], ["create", "approve"]))
_m("K8-25", "A non-system ServiceAccount that can create pod-spawning workloads.",
   *_rbac("K8-25", ["apps", "batch"], ["deployments", "daemonsets", "jobs", "cronjobs", "statefulsets"], ["create"]))
_m("K8-26", "A non-system ServiceAccount granted nodes/proxy.", *_rbac("K8-26", [""], ["nodes/proxy"], ["get", "create"]))
_m("K8-27", "A non-system ServiceAccount that can create mutatingwebhookconfigurations.",
   *_rbac("K8-27", ["admissionregistration.k8s.io"], ["mutatingwebhookconfigurations"], ["create"]))
_m("K8-28", "A non-system ServiceAccount that can create validatingwebhookconfigurations.",
   *_rbac("K8-28", ["admissionregistration.k8s.io"], ["validatingwebhookconfigurations"], ["create"]))
_m("K8-29", "A non-system ServiceAccount bound to a wildcard RBAC rule (*/*/*).", *_rbac("K8-29", ["*"], ["*"], ["*"]))

# ---- Kubernetes: version / host-state / cloud (not auto-armed) ----
for _v, _p in {
    "K8-06": "kubelet :10250 with anonymous-auth=true (control-plane reconfigure — not auto-armed).",
    "K8-11": "The node admin kubeconfig left group/world-readable (host-state — not auto-armed).",
    "K8-12": "kube-apiserver with anonymous-auth=true (control-plane reconfigure — not auto-armed).",
    "K8-17": "k3s installed without --secrets-encryption (install-time default — ambient).",
    "K8-18": "kernel version vulnerable to the pidfd FD-steal CVE.",
    "K8-30": "kubelet read-only port :10255 enabled (kubelet reconfigure — not auto-armed).",
    "K8-31": "etcd reachable on 2379/2380 without client-cert auth (not auto-armed).",
    "K8-32": "kubelet authorization-mode=AlwaysAllow (kubelet reconfigure — not auto-armed).",
    "K8-33": "kubeadm /etc/kubernetes/manifests writable (kubeadm-only path — host-state).",
    "K8-35": "kubeadm admin.conf or CA key group/world-readable (host-state — not auto-armed).",
    "K8-38": "No namespace enforces PodSecurity restricted and no admission webhook (cluster posture).",
    "K8-40": "No NetworkPolicy exists cluster-wide (cluster posture).",
    "K8-44": "kube-apiserver < 1.10.11/1.11.5/1.12.3 (CVE-2018-1002105).",
    "K8-46": "kubelet < 1.19.16/1.20.11/1.21.5 (CVE-2021-25741 subPath).",
    "K8-47": "ingress-nginx controller < 1.11.5 / 1.12.1 (IngressNightmare).",
    "K8-48": "CRI-O < 1.23.2 (cr8escape CVE-2022-0811).",
    "K8-49": "kernel < ~5.17 reachable from an unprivileged pod (CVE-2022-0185).",
    "K8-50": "A cloud IMDS (AWS/GCP/Azure) reachable from pods — cloud clusters only.",
    "K8-51": "A dockerconfigjson imagePullSecret present (ambient).",
    "K8-52": "Credential-looking values in a ConfigMap or container env (ambient).",
    "K8-54": "Legacy Helm v2 Tiller deployed in-cluster (not auto-armed).",
    "K8-NA": "A cloud instance-metadata service present — absent on Proxmox (expected n-a).",
}.items():
    _m(_v, _p)


def apply(scenarios):
    """Stamp preconditions / arm_sh / cleanup_sh onto the registry from METADATA."""
    for s in scenarios:
        meta = METADATA.get(s.id)
        if not meta:
            continue
        s.preconditions = meta["pre"]
        s.arm_sh = meta.get("arm")
        s.cleanup_sh = meta.get("cleanup")
