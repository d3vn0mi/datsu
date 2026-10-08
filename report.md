# datsu validation report

**Run marker:** `RS_lab2`  ·  **When:** 2026-10-08 09:09

Two questions per scenario: **Q1** — can datsu detect the precondition? **Q2** — can datsu exploit it? Each armed on a disposable lab, torn down after.

## Summary

- Scenarios validated: **93**
- Q1 detection: **68 detected** (armed), 0 present ambient, **2 missed**
- Q2 exploitation: **26 exploited**, 17 failed, 50 N/A-by-design (version / precondition / n-a)

| Scenario | Vector | Sev | Q1 detect | Q2 exploit |
|----|----|----|----|----|
| DK-01 | privileged container (docker run --privileged) | CRITICAL | ✅ detected | ✅ exploited |
| DK-02 | docker.sock bind-mounted into a container | CRITICAL | ✅ detected | ✅ exploited |
| DK-03 | SYS_ADMIN + cgroup v1 release_agent breakout | HIGH | ✅ detected | — N/A by design |
| DK-04 | SYS_MODULE capability | HIGH | ✅ detected | — N/A by design |
| DK-05 | DAC_READ_SEARCH capability | HIGH | ✅ detected | — N/A by design |
| DK-06 | SYS_PTRACE + hostPID | HIGH | ✅ detected | — N/A by design |
| DK-07 | sensitive bind mount (-v /:/host) | HIGH | ✅ detected | ✅ exploited |
| DK-08 | host device exposed (--device or /dev bind) | HIGH | ✅ detected | ✅ exploited |
| DK-09 | host network + IPC namespaces | HIGH | ✅ detected | ✅ exploited |
| DK-10 | seccomp unconfined | HIGH | ✅ detected | ✅ exploited |
| DK-11 | no-new-privs off + setuid-root helper | HIGH | ✅ detected | ❌ FAILED |
| DK-12 | dockerd exposed on tcp/2375 | CRITICAL | — absent (arm to test) | ❌ FAILED |
| DK-13 | lab user in the docker group | HIGH | ✅ detected | ✅ exploited |
| DK-14 | rshared bind-propagation mount | MEDIUM | ✅ detected | — N/A by design |
| DK-15 | core_pattern redirected to a handler | HIGH | ✅ detected | ❌ FAILED |
| DK-16 | runc Leaky Vessels (fd leak via WORKDIR trick) | HIGH | — absent (arm to test) | — N/A by design |
| DK-17 | runc 2025 maskedPaths/procfs race family | HIGH | — absent (arm to test) | — N/A by design |
| DK-18 | kernel LPE from an unprivileged container | HIGH | ⚠️ inconclusive | — N/A by design |
| DK-19 | runc /proc/self/exe host-binary overwrite | HIGH | — absent (arm to test) | — N/A by design |
| DK-20 | BuildKit Leaky Vessels build-time escapes | CRITICAL | — absent (arm to test) | — N/A by design |
| DK-21 | runc symlink-exchange mount-destination race | HIGH | — absent (arm to test) | — N/A by design |
| DK-22 | containerd-shim abstract-socket exposure | MEDIUM | — absent (arm to test) | — N/A by design |
| DK-23 | docker cp TOCTOU symlink directory traversal | HIGH | — absent (arm to test) | — N/A by design |
| DK-24 | docker cp libnss chroot library injection | CRITICAL | — absent (arm to test) | — N/A by design |
| DK-25 | cgroup v1 release_agent escape without CAP_SYS_ADMIN | HIGH | — absent (arm to test) | — N/A by design |
| DK-26 | Docker Engine AuthZ plugin bypass (zero-length body) | CRITICAL | — absent (arm to test) | — N/A by design |
| DK-27 | CAP_BPF / CAP_PERFMON added | HIGH | ✅ detected | — N/A by design |
| DK-28 | CAP_SYS_RAWIO added | HIGH | ✅ detected | — N/A by design |
| DK-29 | CAP_SYS_BOOT added | HIGH | ✅ detected | — N/A by design |
| DK-30 | CAP_NET_ADMIN added | HIGH | ✅ detected | — N/A by design |
| DK-31 | CAP_CHECKPOINT_RESTORE added | HIGH | ✅ detected | — N/A by design |
| DK-32 | writable host /sys or /sys/fs/cgroup bind-mount | HIGH | ✅ detected | ✅ exploited |
| DK-33 | writable host /proc bind-mount / masked-paths disabl | HIGH | ✅ detected | — N/A by design |
| DK-34 | /dev/mem, /dev/kmem or /dev/port exposed | CRITICAL | ✅ detected | — N/A by design |
| DK-35 | AppArmor disabled (apparmor=unconfined) standalone | MEDIUM | ✅ detected | — N/A by design |
| DK-36 | SELinux label disabled (label:disable) | HIGH | ✅ detected | — N/A by design |
| DK-37 | containerd / BuildKit socket bind-mounted into a con | CRITICAL | ✅ detected | — N/A by design |
| DK-38 | host /lib/modules or /boot bind-mounted | HIGH | ✅ detected | — N/A by design |
| K8-01 | ServiceAccount bound to a Role granting create pods | CRITICAL | ✅ detected | ✅ exploited |
| K8-02 | privileged pod | CRITICAL | ✅ detected | ❌ FAILED |
| K8-03 | hostPath mount of / | CRITICAL | ❌ MISSED | ❌ FAILED |
| K8-04 | hostPID/hostNetwork/hostIPC pod | HIGH | ✅ detected | ❌ FAILED |
| K8-05 | privileged DaemonSet | HIGH | ✅ detected | ❌ FAILED |
| K8-06 | kubelet :10250 anonymous-auth | HIGH | ✅ detected | ✅ exploited |
| K8-07 | namespace without PSA enforce=restricted | HIGH | ✅ detected | ❌ FAILED |
| K8-08 | NET_RAW ARP/DNS spoof between co-located pods | MEDIUM | ✅ detected | ❌ FAILED |
| K8-09 | embedded etcd read bypassing RBAC | CRITICAL | ✅ detected | ❌ FAILED |
| K8-10 | static-pod manifest directory writable | HIGH | ✅ detected | ❌ FAILED |
| K8-11 | node admin kubeconfig left group/world-readable | HIGH | ✅ detected | ✅ exploited |
| K8-12 | apiserver anonymous-auth | CRITICAL | ❌ MISSED | ❌ FAILED |
| K8-13 | system:anonymous bound to a ClusterRole | CRITICAL | ✅ detected | ✅ exploited |
| K8-14 | ServiceAccount can create PersistentVolumes (hostPat | HIGH | ✅ detected | ✅ exploited |
| K8-15 | ServiceAccount can create pods/ephemeralcontainers | HIGH | ✅ detected | ✅ exploited |
| K8-16 | ClusterRole grants escalate/bind | HIGH | ✅ detected | ✅ exploited |
| K8-17 | Secrets stored unencrypted in etcd | MEDIUM | ✅ detected | ❌ FAILED |
| K8-18 | pidfd FD-steal (seccomp unset + namespace not Restri | HIGH | ⚠️ inconclusive | — N/A by design |
| K8-19 | SA can create pods/exec (exec into any pod) | HIGH | ✅ detected | ✅ exploited |
| K8-20 | SA can create pods/attach (attach to any pod) | HIGH | ✅ detected | ✅ exploited |
| K8-21 | SA can read Secrets cluster-wide (get/list secrets) | CRITICAL | ✅ detected | ✅ exploited |
| K8-22 | SA can create serviceaccounts/token (TokenRequest) | HIGH | ✅ detected | ❌ FAILED |
| K8-23 | SA granted impersonate (users/groups/serviceaccounts | CRITICAL | ✅ detected | ❌ FAILED |
| K8-24 | SA can approve certificatesigningrequests | CRITICAL | ✅ detected | ✅ exploited |
| K8-25 | SA can create pod-spawning workloads (Deployments/Jo | CRITICAL | ✅ detected | ✅ exploited |
| K8-26 | SA granted nodes/proxy (reach each node's kubelet) | CRITICAL | ✅ detected | ✅ exploited |
| K8-27 | SA can create mutatingwebhookconfigurations | CRITICAL | ✅ detected | ✅ exploited |
| K8-28 | SA can create validatingwebhookconfigurations | HIGH | ✅ detected | ✅ exploited |
| K8-29 | SA bound to a wildcard rule (apiGroups/resources/ver | CRITICAL | ✅ detected | ✅ exploited |
| K8-30 | kubelet read-only port :10255 exposed | HIGH | ✅ detected | ✅ exploited |
| K8-31 | network-reachable etcd (2379/2380) without client-ce | CRITICAL | — absent (arm to test) | ❌ FAILED |
| K8-32 | kubelet authorization-mode=AlwaysAllow | CRITICAL | ✅ detected | — N/A by design |
| K8-33 | kubeadm static-pod manifests dir writable (/etc/kube | CRITICAL | ✅ detected | — N/A by design |
| K8-34 | pod hostPath-mounts a sensitive node path (socket /  | CRITICAL | ✅ detected | — N/A by design |
| K8-35 | kubeadm admin.conf or cluster CA key group/world-rea | CRITICAL | ✅ detected | — N/A by design |
| K8-36 | pod requests dangerous Linux capabilities (securityC | HIGH | ✅ detected | — N/A by design |
| K8-37 | legacy long-lived ServiceAccount-token Secrets prese | HIGH | ✅ detected | — N/A by design |
| K8-38 | no cluster-wide admission guardrail (no namespace en | MEDIUM | ✅ detected | — N/A by design |
| K8-39 | ServiceAccount token auto-mounted into pods | MEDIUM | ✅ detected | — N/A by design |
| K8-40 | no default-deny NetworkPolicy (flat pod network) | MEDIUM | ✅ detected | — N/A by design |
| K8-41 | pod with shareProcessNamespace: true | MEDIUM | ✅ detected | — N/A by design |
| K8-42 | pod runs as root (no runAsNonRoot / runAsUser 0) | MEDIUM | ✅ detected | — N/A by design |
| K8-43 | pod binds a hostPort | MEDIUM | ✅ detected | — N/A by design |
| K8-44 | kube-apiserver proxy/upgrade privilege escalation | CRITICAL | — absent (arm to test) | — N/A by design |
| K8-45 | gitRepo volume in use (deprecated; kubelet runs git  | HIGH | ✅ detected | — N/A by design |
| K8-46 | kubelet subPath symlink-swap race | HIGH | — absent (arm to test) | — N/A by design |
| K8-47 | ingress-nginx IngressNightmare unauthenticated RCE | CRITICAL | — absent (arm to test) | — N/A by design |
| K8-48 | CRI-O cr8escape (pod-supplied sysctl -> host command | CRITICAL | ⚠️ inconclusive | — N/A by design |
| K8-49 | kernel fs_context heap overflow (LPE from a pod) | HIGH | — absent (arm to test) | — N/A by design |
| K8-50 | cloud IMDS credential theft reachable from the node/ | CRITICAL | — absent (arm to test) | ❌ FAILED |
| K8-51 | imagePullSecrets / dockerconfigjson present (registr | MEDIUM | — absent (arm to test) | — N/A by design |
| K8-52 | secrets embedded in ConfigMaps / container env liter | HIGH | — absent (arm to test) | — N/A by design |
| K8-53 | unpinned / mutable image references (:latest or no d | MEDIUM | ✅ detected | — N/A by design |
| K8-54 | legacy Helm v2 Tiller in-cluster (unauthenticated :4 | CRITICAL | ✅ detected | ✅ exploited |
| K8-NA | cloud IMDS (169.254.169.254) — not present on Proxmo | INFO | — absent (arm to test) | — N/A by design |

## Per-scenario detail

### DK-01 — privileged container (docker run --privileged)

*docker · CRITICAL · config/concrete · triage B1*

- **Preconditions:** A container started with --privileged (all caps, no seccomp/apparmor, device access).
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk15`
- **Q2 — exploit:** ✅ exploited — `host /root write via --privileged + nsenter -t1 (ESCAPE_DK-01_RS_lab2)`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-01 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-01 --privileged alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-01`
  - *Exploit:* `datsu exploit --id DK-01 --marker <token>`

### DK-02 — docker.sock bind-mounted into a container

*docker · CRITICAL · config/documented · triage C1*

- **Preconditions:** A container with the Docker socket bind-mounted (-v /var/run/docker.sock).
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-02`
- **Q2 — exploit:** ✅ exploited — `host write via mounted docker.sock Engine API (ESCAPE_DK-02_RS_lab2)`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-02 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-02 -v /var/run/docker.sock:/run/docker.sock alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-02`
  - *Exploit:* `datsu exploit --id DK-02 --marker <token>`

### DK-03 — SYS_ADMIN + cgroup v1 release_agent breakout

*docker · HIGH · config/precondition · triage B2*

- **Preconditions:** A container with CAP_SYS_ADMIN (and, for the full breakout, a cgroup-v1 host + apparmor=unconfined).
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-03`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — release_agent breakout needs cgroup v1; the host-overlay path discovery is storage-driver specific — not a safe single-shot (cyber_gate).`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-03 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-03 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-03`
  - *Exploit:* `datsu exploit --id DK-03 --marker <token>`

### DK-04 — SYS_MODULE capability

*docker · HIGH · config/precondition · triage B4*

- **Preconditions:** A container granted CAP_SYS_MODULE.
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-04`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — SYS_MODULE loads a kernel module, but proving it needs a module blob + compiler offline — out of scope for a bounded one-shot (cyber_gate).`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-04 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-04 --cap-add=SYS_MODULE alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-04`
  - *Exploit:* `datsu exploit --id DK-04 --marker <token>`

### DK-05 — DAC_READ_SEARCH capability

*docker · HIGH · config/precondition · triage B5*

- **Preconditions:** A container granted CAP_DAC_READ_SEARCH.
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-05`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — open_by_handle_at (shocker) PoC needs a compiled binary — not a bounded one-shot (cyber_gate).`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-05 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-05 --cap-add=DAC_READ_SEARCH alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-05`
  - *Exploit:* `datsu exploit --id DK-05 --marker <token>`

### DK-06 — SYS_PTRACE + hostPID

*docker · HIGH · config/precondition · triage B3*

- **Preconditions:** A container with host PID namespace (--pid=host) and CAP_SYS_PTRACE.
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-06`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — Docker-default AppArmor denies /proc/1/{environ,mem}; a genuine host-process read needs apparmor=unconfined too.`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-06 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-06 --pid=host --cap-add=SYS_PTRACE alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-06`
  - *Exploit:* `datsu exploit --id DK-06 --marker <token>`

### DK-07 — sensitive bind mount (-v /:/host)

*docker · HIGH · config/concrete · triage C2*

- **Preconditions:** A container bind-mounting the host root filesystem (-v /:/host).
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-07`
- **Q2 — exploit:** ✅ exploited — `host write via -v /:/host (ESCAPE_DK-07_RS_lab2)`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-07 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-07 -v /:/host alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-07`
  - *Exploit:* `datsu exploit --id DK-07 --marker <token>`

### DK-08 — host device exposed (--device or /dev bind)

*docker · HIGH · config/documented · triage C4*

- **Preconditions:** A container with a raw host block device exposed (--device).
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-34`
- **Q2 — exploit:** ✅ exploited — `read raw host device /dev/sda from container (ESCAPE_DK-08_RS_lab2); fs-magic sampled: 353c220                             *          �      �37222022036630220`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-08 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-08 --device=/dev/null alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-08`
  - *Exploit:* `datsu exploit --id DK-08 --marker <token>`

### DK-09 — host network + IPC namespaces

*docker · HIGH · config/documented · triage C6*

- **Preconditions:** A container sharing host network and IPC namespaces (--network=host --ipc=host).
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-09`
- **Q2 — exploit:** ✅ exploited — `host-only apiserver:6443 / kubelet:10250 reachable from --network=host container (ESCAPE_DK-09_RS_lab2): {`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-09 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-09 --network=host --ipc=host alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-09`
  - *Exploit:* `datsu exploit --id DK-09 --marker <token>`

### DK-10 — seccomp unconfined

*docker · HIGH · config/documented · triage B8*

- **Preconditions:** A container running with seccomp disabled (--security-opt seccomp=unconfined).
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-10`
- **Q2 — exploit:** ✅ exploited — `seccomp filter disabled in container (ESCAPE_DK-10_RS_lab2): Seccomp:	0`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-10 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-10 --security-opt seccomp=unconfined alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-10`
  - *Exploit:* `datsu exploit --id DK-10 --marker <token>`

### DK-11 — no-new-privs off + setuid-root helper

*docker · HIGH · config/concrete · triage B10*

- **Preconditions:** A container with a setuid-root helper reachable by a non-root user (no-new-privs off).
- **Q1 — detect precondition:** ✅ detected — `fd239c19c5c9:/usr/local/bin/esc-helper`
- **Q2 — exploit:** ❌ FAILED — `uid-1000 user -> root via setuid helper (ESCAPE_DK-11_RS_lab2):`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk11 >/dev/null 2>&1; docker run -d --name datsu-arm-dk11 alpine sleep 600 >/dev/null; docker exec datsu-arm-dk11 sh -c 'cp /bin/busybox /usr/local/bin/esc-helper && chmod 4755 /usr/local/bin/esc-helper'
    ```
  - *Detect:* `datsu detect --only DK-11`
  - *Exploit:* `datsu exploit --id DK-11 --marker <token>`

### DK-12 — dockerd exposed on tcp/2375

*docker · CRITICAL · config/documented · triage C8*

- **Preconditions:** dockerd listening on an unauthenticated TCP socket (tcp/2375). (host daemon reconfigure — not auto-armed)
- **Q1 — detect precondition:** — absent (arm to test)
- **Q2 — exploit:** ❌ FAILED — `host write via unauth dockerd tcp/2375 (ESCAPE_DK-12_RS_lab2)`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only DK-12`
  - *Exploit:* `datsu exploit --id DK-12 --marker <token>`

### DK-13 — lab user in the docker group

*docker · HIGH · config/concrete*

- **Preconditions:** A local user who is a member of the docker group.
- **Q1 — detect precondition:** ✅ detected — `datsu-arm-u`
- **Q2 — exploit:** ✅ exploited — `host write as docker-group user datsu-arm-u (ESCAPE_DK-13_RS_lab2)`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    id -u datsu-arm-u >/dev/null 2>&1 || useradd -m -s /bin/sh datsu-arm-u 2>/dev/null; usermod -aG docker datsu-arm-u
    ```
  - *Detect:* `datsu detect --only DK-13`
  - *Exploit:* `datsu exploit --id DK-13 --marker <token>`

### DK-14 — rshared bind-propagation mount

*docker · MEDIUM · config/precondition*

- **Preconditions:** A container with an rshared bind-propagation mount.
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-14`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — The host-mount-escape via rshared propagation is a multi-step race with no safe single-shot command.`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-14 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-14 --mount type=bind,src=/tmp,dst=/mnt/datsu,bind-propagation=rshared alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-14`
  - *Exploit:* `datsu exploit --id DK-14 --marker <token>`

### DK-15 — core_pattern redirected to a handler

*docker · HIGH · config/documented · triage C3*

- **Preconditions:** A privileged container that rewrote the host core_pattern to a pipe handler.
- **Q1 — detect precondition:** ✅ detected — `|/tmp/datsu-h %P`
- **Q2 — exploit:** ❌ FAILED — `container-set core_pattern ran a host-root handler (ESCAPE_DK-15_RS_lab2)`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk15 >/dev/null 2>&1; docker run -d --name datsu-arm-dk15 --privileged alpine sleep 600 >/dev/null; docker exec datsu-arm-dk15 sh -c 'echo "|/tmp/datsu-h %P" > /proc/sys/kernel/core_pattern'
    ```
  - *Detect:* `datsu detect --only DK-15`
  - *Exploit:* `datsu exploit --id DK-15 --marker <token>`

### DK-16 — runc Leaky Vessels (fd leak via WORKDIR trick)

*docker · HIGH · version/documented · triage A2 · CVE-2024-21626*

- **Preconditions:** runc version in the Leaky Vessels (CVE-2024-21626) vulnerable range.
- **Q1 — detect precondition:** — absent (arm to test) — `runc 1.5.1 (fixed in >= 1.1.12)`
- **Q2 — exploit:** — N/A by design — `version/CVE precondition — detection only (cyber_gate: no live exploitation of a version-pinned component)`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only DK-16`
  - *Exploit:* `datsu exploit --id DK-16 --marker <token>`

### DK-17 — runc 2025 maskedPaths/procfs race family

*docker · HIGH · version/documented · triage A3*

- **Preconditions:** runc version in the 2025 maskedPaths/procfs race range.
- **Q1 — detect precondition:** — absent (arm to test) — `runc 1.5.1 (fixed in >= 1.2.8)`
- **Q2 — exploit:** — N/A by design — `version/CVE precondition — detection only (cyber_gate: no live exploitation of a version-pinned component)`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only DK-17`
  - *Exploit:* `datsu exploit --id DK-17 --marker <token>`

### DK-18 — kernel LPE from an unprivileged container

*docker · HIGH · version/documented · triage A1*

- **Preconditions:** kernel version in the container-LPE vulnerable window.
- **Q1 — detect precondition:** ⚠️ inconclusive — `kernel 6.8.0-139-generic — verify against the published kernel-LPE advisory floor (placeholder in the pack)`
- **Q2 — exploit:** — N/A by design — `version/CVE precondition — detection only (cyber_gate: no live exploitation of a version-pinned component)`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only DK-18`
  - *Exploit:* `datsu exploit --id DK-18 --marker <token>`

### DK-19 — runc /proc/self/exe host-binary overwrite

*docker · HIGH · version/documented · CVE-2019-5736*

- **Preconditions:** runc <= 1.0.0-rc6 / Docker < 18.09.2 (CVE-2019-5736).
- **Q1 — detect precondition:** — absent (arm to test) — `docker: 29.8.2 (fixed >= 18.9.2)`
- **Q2 — exploit:** — N/A by design — `version/CVE precondition — detection only (cyber_gate: no live exploitation of a version-pinned component)`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only DK-19`
  - *Exploit:* `datsu exploit --id DK-19 --marker <token>`

### DK-20 — BuildKit Leaky Vessels build-time escapes

*docker · CRITICAL · version/documented · CVE-2024-23651*

- **Preconditions:** BuildKit < 0.12.5 / Docker < 24.0.9 or < 25.0.2 (Leaky Vessels).
- **Q1 — detect precondition:** — absent (arm to test) — `buildkit: 0.37.1 (fixed >= 0.12.5)`
- **Q2 — exploit:** — N/A by design — `version/CVE precondition — detection only (cyber_gate: no live exploitation of a version-pinned component)`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only DK-20`
  - *Exploit:* `datsu exploit --id DK-20 --marker <token>`

### DK-21 — runc symlink-exchange mount-destination race

*docker · HIGH · version/documented · CVE-2021-30465*

- **Preconditions:** runc < 1.0.0-rc95 (CVE-2021-30465).
- **Q1 — detect precondition:** — absent (arm to test) — `runc 1.5.1 (fixed in >= 1.0.2)`
- **Q2 — exploit:** — N/A by design — `version/CVE precondition — detection only (cyber_gate: no live exploitation of a version-pinned component)`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only DK-21`
  - *Exploit:* `datsu exploit --id DK-21 --marker <token>`

### DK-22 — containerd-shim abstract-socket exposure

*docker · MEDIUM · version/documented · CVE-2020-15257*

- **Preconditions:** containerd < 1.3.9/1.4.3 plus a host-netns container (CVE-2020-15257).
- **Q1 — detect precondition:** — absent (arm to test) — `containerd: 2.3.6 (fixed >= 1.4.3)`
- **Q2 — exploit:** — N/A by design — `version/CVE precondition — detection only (cyber_gate: no live exploitation of a version-pinned component)`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only DK-22`
  - *Exploit:* `datsu exploit --id DK-22 --marker <token>`

### DK-23 — docker cp TOCTOU symlink directory traversal

*docker · HIGH · version/documented · CVE-2018-15664*

- **Preconditions:** Docker < 18.09.0 (CVE-2018-15664 docker cp).
- **Q1 — detect precondition:** — absent (arm to test) — `docker: 29.8.2 (fixed >= 18.9.0)`
- **Q2 — exploit:** — N/A by design — `version/CVE precondition — detection only (cyber_gate: no live exploitation of a version-pinned component)`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only DK-23`
  - *Exploit:* `datsu exploit --id DK-23 --marker <token>`

### DK-24 — docker cp libnss chroot library injection

*docker · CRITICAL · version/documented · CVE-2019-14271*

- **Preconditions:** Docker == 19.03.0 (CVE-2019-14271 docker cp libnss).
- **Q1 — detect precondition:** — absent (arm to test) — `docker 29.8.2`
- **Q2 — exploit:** — N/A by design — `version/CVE precondition — detection only (cyber_gate: no live exploitation of a version-pinned component)`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only DK-24`
  - *Exploit:* `datsu exploit --id DK-24 --marker <token>`

### DK-25 — cgroup v1 release_agent escape without CAP_SYS_ADMIN

*docker · HIGH · version/documented · CVE-2022-0492*

- **Preconditions:** kernel < 5.17, cgroup v1 reachable, unprivileged userns enabled (CVE-2022-0492).
- **Q1 — detect precondition:** — absent (arm to test) — `kernel 6.8.0-139-generic, cgroup-v1=False, unpriv_userns=True (verify distro backport)`
- **Q2 — exploit:** — N/A by design — `version/CVE precondition — detection only (cyber_gate: no live exploitation of a version-pinned component)`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only DK-25`
  - *Exploit:* `datsu exploit --id DK-25 --marker <token>`

### DK-26 — Docker Engine AuthZ plugin bypass (zero-length body)

*docker · CRITICAL · version/documented · CVE-2024-41110*

- **Preconditions:** Docker with an AuthZ plugin configured and engine < 23.0.14/27.1.1 (CVE-2024-41110).
- **Q1 — detect precondition:** — absent (arm to test) — `authz-plugin=False, docker 29.8.2 (fixed >= 27.1.1 / 23.0.14)`
- **Q2 — exploit:** — N/A by design — `version/CVE precondition — detection only (cyber_gate: no live exploitation of a version-pinned component)`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only DK-26`
  - *Exploit:* `datsu exploit --id DK-26 --marker <token>`

### DK-27 — CAP_BPF / CAP_PERFMON added

*docker · HIGH · config/precondition*

- **Preconditions:** A container granted CAP_BPF or CAP_PERFMON.
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-27`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — eBPF program load / kernel tracing — kernel read/write primitives; exploit needs a bpf toolchain (offline).`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-27 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-27 --cap-add=BPF --cap-add=PERFMON alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-27`
  - *Exploit:* `datsu exploit --id DK-27 --marker <token>`

### DK-28 — CAP_SYS_RAWIO added

*docker · HIGH · config/precondition*

- **Preconditions:** A container granted CAP_SYS_RAWIO.
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-28`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — iopl/ioperm + raw I/O-port and /dev/mem-class access; exploit is hardware/offline-tooling specific.`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-28 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-28 --cap-add=SYS_RAWIO alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-28`
  - *Exploit:* `datsu exploit --id DK-28 --marker <token>`

### DK-29 — CAP_SYS_BOOT added

*docker · HIGH · config/precondition*

- **Preconditions:** A container granted CAP_SYS_BOOT.
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-29`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — reboot()/kexec_load() — host DoS or boot a kexec'd attacker kernel.`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-29 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-29 --cap-add=SYS_BOOT alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-29`
  - *Exploit:* `datsu exploit --id DK-29 --marker <token>`

### DK-30 — CAP_NET_ADMIN added

*docker · HIGH · config/precondition*

- **Preconditions:** A container granted CAP_NET_ADMIN.
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-30`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — reconfigure host interfaces/routes/iptables/nftables (esp. with host networking) — MITM / firewall tamper.`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-30 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-30 --cap-add=NET_ADMIN alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-30`
  - *Exploit:* `datsu exploit --id DK-30 --marker <token>`

### DK-31 — CAP_CHECKPOINT_RESTORE added

*docker · HIGH · config/precondition*

- **Preconditions:** A container granted CAP_CHECKPOINT_RESTORE.
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-31`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — grants open_by_handle_at() (same primitive as DK-05/DAC_READ_SEARCH) — read host files by handle; needs a compiled PoC.`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-31 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-31 --cap-add=CHECKPOINT_RESTORE alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-31`
  - *Exploit:* `datsu exploit --id DK-31 --marker <token>`

### DK-32 — writable host /sys or /sys/fs/cgroup bind-mount

*docker · HIGH · config/documented*

- **Preconditions:** A container with a writable host /sys (or /sys/fs/cgroup) bind-mount.
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-32`
- **Q2 — exploit:** ✅ exploited — `writable host /sys reachable from container a221a4e747f64ef125f5559a389bb8894fe1760d7b60765df9e230f6a7cf94c1 (ESCAPE_DK-32_RS_lab2)`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-32 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-32 -v /sys:/host-sys alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-32`
  - *Exploit:* `datsu exploit --id DK-32 --marker <token>`

### DK-33 — writable host /proc bind-mount / masked-paths disabled

*docker · HIGH · config/precondition*

- **Preconditions:** A container with a writable host /proc bind-mount (or masked-paths disabled).
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-33`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — write /proc/sysrq-trigger (host control) or /proc/<pid>/mem (inject into host process). Needs a host /proc mount or disabled maskedPaths.`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-33 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-33 -v /proc:/host-proc alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-33`
  - *Exploit:* `datsu exploit --id DK-33 --marker <token>`

### DK-34 — /dev/mem, /dev/kmem or /dev/port exposed

*docker · CRITICAL · config/precondition*

- **Preconditions:** A container with /dev/mem, /dev/kmem or /dev/port exposed.
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-34`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — direct physical/kernel memory access — full host compromise; exploit needs a compiled memory-editing PoC.`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-34 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-34 --device=/dev/mem alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-34`
  - *Exploit:* `datsu exploit --id DK-34 --marker <token>`

### DK-35 — AppArmor disabled (apparmor=unconfined) standalone

*docker · MEDIUM · config/precondition*

- **Preconditions:** A container with AppArmor disabled (apparmor=unconfined).
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-35`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — drops the docker-default AppArmor profile; broadens many other primitives (e.g. unlocks DK-06 /proc/1/mem).`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-35 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-35 --security-opt apparmor=unconfined alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-35`
  - *Exploit:* `datsu exploit --id DK-35 --marker <token>`

### DK-36 — SELinux label disabled (label:disable)

*docker · HIGH · config/precondition*

- **Preconditions:** A container with SELinux labelling disabled (label:disable) on an enforcing host.
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-36`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — removes SELinux confinement on an enforcing host — container processes run unconfined_t.`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-36 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-36 --security-opt label=disable alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-36`
  - *Exploit:* `datsu exploit --id DK-36 --marker <token>`

### DK-37 — containerd / BuildKit socket bind-mounted into a container

*docker · CRITICAL · config/precondition*

- **Preconditions:** A container with the containerd/buildkit socket bind-mounted.
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-37`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — the containerd (or buildkitd) socket is root-on-host, exactly like docker.sock (DK-02); drive it to run a privileged task.`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-37 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-37 -v /run/containerd/containerd.sock:/run/containerd/containerd.sock alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-37`
  - *Exploit:* `datsu exploit --id DK-37 --marker <token>`

### DK-38 — host /lib/modules or /boot bind-mounted

*docker · HIGH · config/precondition*

- **Preconditions:** A container bind-mounting host /lib/modules or /boot.
- **Q1 — detect precondition:** ✅ detected — `/datsu-arm-dk-38`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — with CAP_SYS_MODULE (DK-04) a mounted /lib/modules lets a crafted module load into the host kernel.`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    docker rm -f datsu-arm-dk-38 >/dev/null 2>&1; docker run -d --name datsu-arm-dk-38 -v /lib/modules:/lib/modules alpine sleep 600 >/dev/null
    ```
  - *Detect:* `datsu detect --only DK-38`
  - *Exploit:* `datsu exploit --id DK-38 --marker <token>`

### K8-01 — ServiceAccount bound to a Role granting create pods

*k8s · CRITICAL · config/documented · triage D1*

- **Preconditions:** A non-system ServiceAccount bound to a Role granting create on pods.
- **Q1 — detect precondition:** ✅ detected — `SA can create pods: datsu-arm:datsu-arm-k8-01-sa, datsu-arm:datsu-arm-k8-29-sa`
- **Q2 — exploit:** ✅ exploited — `privileged hostPID pod nsenter-wrote host /root (ESCAPE_K8-01_RS_lab2)`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm create sa datsu-arm-k8-01-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    cat <<EOF | kubectl apply -f - >/dev/null 2>&1
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata: {name: datsu-arm-k8-01-role, namespace: datsu-arm}
    rules: [{apiGroups: [""], resources: ["pods"], verbs: ["create"]}]
    EOF
    kubectl -n datsu-arm create rolebinding datsu-arm-k8-01-role-rb --role=datsu-arm-k8-01-role --serviceaccount=datsu-arm:datsu-arm-k8-01-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-01`
  - *Exploit:* `datsu exploit --id K8-01 --marker <token>`

### K8-02 — privileged pod

*k8s · CRITICAL · config/concrete · triage D2*

- **Preconditions:** A privileged pod (securityContext.privileged=true).
- **Q1 — detect precondition:** ✅ detected — `esc-x/esc-x-k801`
- **Q2 — exploit:** ❌ FAILED — `privileged pod -> host /root via nsenter (ESCAPE_K8-02_RS_lab2)`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm run datsu-arm-k8-02 --image=alpine --restart=Never --overrides='{"spec":{"containers":[{"name":"c","image":"alpine","command":["sleep","600"],"securityContext":{"privileged":true}}]}}' --command -- sleep 600 >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-02`
  - *Exploit:* `datsu exploit --id K8-02 --marker <token>`

### K8-03 — hostPath mount of /

*k8s · CRITICAL · config/concrete · triage D2*

- **Preconditions:** A pod with a hostPath volume mounting the node root (/).
- **Q1 — detect precondition:** ❌ MISSED
- **Q2 — exploit:** ❌ FAILED — `hostPath / pod wrote node /root (ESCAPE_K8-03_RS_lab2)`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm run datsu-arm-k8-03 --image=alpine --restart=Never --overrides='{"spec":{"containers":[{"name":"c","image":"alpine","command":["sleep","600"],"volumeMounts":[{"name":"h","mountPath":"/host"}]}],"volumes":[{"name":"h","hostPath":{"path":"/"}}]}}' --command -- sleep 600 >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-03`
  - *Exploit:* `datsu exploit --id K8-03 --marker <token>`

### K8-04 — hostPID/hostNetwork/hostIPC pod

*k8s · HIGH · config/documented · triage D2*

- **Preconditions:** A pod sharing host PID/Network/IPC namespaces.
- **Q1 — detect precondition:** ✅ detected — `esc-x/esc-x-k801`
- **Q2 — exploit:** ❌ FAILED — `hostPID pod sees node PID 1 (ESCAPE_K8-04_RS_lab2):`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm run datsu-arm-k8-04 --image=alpine --restart=Never --overrides='{"spec":{"hostPID":true,"hostNetwork":true,"hostIPC":true,"containers":[{"name":"c","image":"alpine","command":["sleep","600"]}]}}' --command -- sleep 600 >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-04`
  - *Exploit:* `datsu exploit --id K8-04 --marker <token>`

### K8-05 — privileged DaemonSet

*k8s · HIGH · config/documented · triage D7*

- **Preconditions:** A privileged DaemonSet.
- **Q1 — detect precondition:** ✅ detected — `kube-system/datsu-arm-k805`
- **Q2 — exploit:** ❌ FAILED — `privileged pod read raw node disk (ESCAPE_K8-05_RS_lab2):`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    cat <<EOF | kubectl apply -f - >/dev/null 2>&1
    apiVersion: apps/v1
    kind: DaemonSet
    metadata: {name: datsu-arm-k805, namespace: kube-system}
    spec: {selector: {matchLabels: {app: datsu-arm-k805}}, template: {metadata: {labels: {app: datsu-arm-k805}}, spec: {containers: [{name: c, image: alpine, command: ["sleep","600"], securityContext: {privileged: true}}]}}}
    EOF
    ```
  - *Detect:* `datsu detect --only K8-05`
  - *Exploit:* `datsu exploit --id K8-05 --marker <token>`

### K8-06 — kubelet :10250 anonymous-auth

*k8s · HIGH · config/documented · triage D4*

- **Preconditions:** kubelet :10250 with anonymous-auth=true (control-plane reconfigure — not auto-armed).
- **Q1 — detect precondition:** ✅ detected — `kubelet /pods -> 200`
- **Q2 — exploit:** ✅ exploited — `anon kubelet /pods (ESCAPE_K8-06_RS_lab2): {"kind":"PodList","apiVersion":"v1","metadata":{},"items":[{"metadata":{"name":"metrics-server-6dc596dfb8-drt7r","gen`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    (control-plane / host-state — armed by the lab setup)
    ```
  - *Detect:* `datsu detect --only K8-06`
  - *Exploit:* `datsu exploit --id K8-06 --marker <token>`

### K8-07 — namespace without PSA enforce=restricted

*k8s · HIGH · config/documented · triage D3*

- **Preconditions:** A namespace without Pod Security 'restricted' enforcement.
- **Q1 — detect precondition:** ✅ detected — `datsu-arm`
- **Q2 — exploit:** ❌ FAILED — `privileged pod admitted + Running in a non-restricted ns (ESCAPE_K8-07_RS_lab2)`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-07`
  - *Exploit:* `datsu exploit --id K8-07 --marker <token>`

### K8-08 — NET_RAW ARP/DNS spoof between co-located pods

*k8s · MEDIUM · config/documented*

- **Preconditions:** Two running pods retaining NET_RAW on a shared pod network.
- **Q1 — detect precondition:** ✅ detected — `datsu-arm/datsu-arm-k8-34`
- **Q2 — exploit:** ❌ FAILED — `NET_RAW L2 probe pod-a -> pod-b  (ESCAPE_K8-08_RS_lab2):`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm run datsu-arm-k808 --image=alpine --restart=Never --command -- sleep 600 >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-08`
  - *Exploit:* `datsu exploit --id K8-08 --marker <token>`

### K8-09 — embedded etcd read bypassing RBAC

*k8s · CRITICAL · config/documented · triage D14*

- **Preconditions:** A Secret stored in the node's embedded etcd (on-disk db root-readable).
- **Q1 — detect precondition:** ✅ detected — `readable etcd db: /var/lib/rancher/k3s/server/db/etcd/member/snap/db`
- **Q2 — exploit:** ❌ FAILED — `Secret canary read in cleartext from on-disk etcd (ESCAPE_K8-09_RS_lab2)`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm create secret generic datsu-arm-k809 --from-literal=x=y >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-09`
  - *Exploit:* `datsu exploit --id K8-09 --marker <token>`

### K8-10 — static-pod manifest directory writable

*k8s · HIGH · config/documented · triage D8*

- **Preconditions:** The k3s server manifests directory left world/group-writable.
- **Q1 — detect precondition:** ✅ detected — `/var/lib/rancher/k3s/server/manifests 777`
- **Q2 — exploit:** ❌ FAILED — `dropped manifest auto-applied by k3s as root (ESCAPE_K8-10_RS_lab2)`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    d=/var/lib/rancher/k3s/server/manifests; [ -d "$d" ] && { stat -c "%a" "$d" > /tmp/.datsu-k810; chmod 777 "$d"; }
    ```
  - *Detect:* `datsu detect --only K8-10`
  - *Exploit:* `datsu exploit --id K8-10 --marker <token>`

### K8-11 — node admin kubeconfig left group/world-readable

*k8s · HIGH · config/documented · triage D9*

- **Preconditions:** The node admin kubeconfig left group/world-readable (host-state — not auto-armed).
- **Q1 — detect precondition:** ✅ detected — `/etc/rancher/k3s/k3s.yaml 644`
- **Q2 — exploit:** ✅ exploited — `cluster-admin via world-readable kubeconfig (ESCAPE_K8-11_RS_lab2): can-i *.*=yes`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    (control-plane / host-state — armed by the lab setup)
    ```
  - *Detect:* `datsu detect --only K8-11`
  - *Exploit:* `datsu exploit --id K8-11 --marker <token>`

### K8-12 — apiserver anonymous-auth

*k8s · CRITICAL · config/documented · triage D4*

- **Preconditions:** kube-apiserver with anonymous-auth=true (control-plane reconfigure — not auto-armed).
- **Q1 — detect precondition:** ❌ MISSED — `apiserver /api (anon) -> 403`
- **Q2 — exploit:** ❌ FAILED — `anon apiserver discovery (ESCAPE_K8-12_RS_lab2): {`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    (control-plane / host-state — armed by the lab setup)
    ```
  - *Detect:* `datsu detect --only K8-12`
  - *Exploit:* `datsu exploit --id K8-12 --marker <token>`

### K8-13 — system:anonymous bound to a ClusterRole

*k8s · CRITICAL · config/concrete · triage D1*

- **Preconditions:** A ClusterRoleBinding granting system:anonymous a ClusterRole.
- **Q1 — detect precondition:** ✅ detected — `datsu-arm-k813`
- **Q2 — exploit:** ✅ exploited — `anonymous cluster read (ESCAPE_K8-13_RS_lab2): pod/datsu-arm-k8-34`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create clusterrolebinding datsu-arm-k813 --clusterrole=view --user=system:anonymous --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-13`
  - *Exploit:* `datsu exploit --id K8-13 --marker <token>`

### K8-14 — ServiceAccount can create PersistentVolumes (hostPath)

*k8s · HIGH · config/documented · triage D1*

- **Preconditions:** A non-system ServiceAccount that can create PersistentVolumes.
- **Q1 — detect precondition:** ✅ detected — `SA can create PersistentVolumes: datsu-arm:datsu-arm-k8-14-sa, datsu-arm:datsu-arm-k8-29-sa`
- **Q2 — exploit:** ✅ exploited — `hostPath PV mapping node / created (ESCAPE_K8-14_RS_lab2)`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm create sa datsu-arm-k8-14-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    cat <<EOF | kubectl apply -f - >/dev/null 2>&1
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata: {name: datsu-arm-k8-14-role, namespace: datsu-arm}
    rules: [{apiGroups: [""], resources: ["persistentvolumes"], verbs: ["create"]}]
    EOF
    kubectl -n datsu-arm create rolebinding datsu-arm-k8-14-role-rb --role=datsu-arm-k8-14-role --serviceaccount=datsu-arm:datsu-arm-k8-14-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-14`
  - *Exploit:* `datsu exploit --id K8-14 --marker <token>`

### K8-15 — ServiceAccount can create pods/ephemeralcontainers

*k8s · HIGH · config/documented · triage D11*

- **Preconditions:** A non-system ServiceAccount that can create pods/ephemeralcontainers.
- **Q1 — detect precondition:** ✅ detected — `SA can create pods/ephemeralcontainers: datsu-arm:datsu-arm-k8-15-sa, datsu-arm:datsu-arm-k8-29-sa`
- **Q2 — exploit:** ✅ exploited — `ephemeral/debug container injected into a running pod (ESCAPE_K8-15_RS_lab2)`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm create sa datsu-arm-k8-15-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    cat <<EOF | kubectl apply -f - >/dev/null 2>&1
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata: {name: datsu-arm-k8-15-role, namespace: datsu-arm}
    rules: [{apiGroups: [""], resources: ["pods/ephemeralcontainers"], verbs: ["create"]}]
    EOF
    kubectl -n datsu-arm create rolebinding datsu-arm-k8-15-role-rb --role=datsu-arm-k8-15-role --serviceaccount=datsu-arm:datsu-arm-k8-15-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-15`
  - *Exploit:* `datsu exploit --id K8-15 --marker <token>`

### K8-16 — ClusterRole grants escalate/bind

*k8s · HIGH · config/documented · triage D12*

- **Preconditions:** A ClusterRole granting escalate/bind on roles.
- **Q1 — detect precondition:** ✅ detected — `datsu-arm-k816`
- **Q2 — exploit:** ✅ exploited — `ClusterRole granting escalate/bind present (ESCAPE_K8-16_RS_lab2): datsu-arm-k816 — a bound principal can self-grant cluster-admin`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    cat <<EOF | kubectl apply -f - >/dev/null 2>&1
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata: {name: datsu-arm-k816}
    rules: [{apiGroups: ["rbac.authorization.k8s.io"], resources: ["clusterroles"], verbs: ["escalate","bind"]}]
    EOF
    ```
  - *Detect:* `datsu detect --only K8-16`
  - *Exploit:* `datsu exploit --id K8-16 --marker <token>`

### K8-17 — Secrets stored unencrypted in etcd

*k8s · MEDIUM · config/documented · triage D10*

- **Preconditions:** k3s installed without --secrets-encryption (install-time default — ambient).
- **Q1 — detect precondition:** ✅ detected — `k3s server running without --secrets-encryption`
- **Q2 — exploit:** ❌ FAILED — `Secret stored in cleartext in etcd (no encryption-at-rest) (ESCAPE_K8-17_RS_lab2)`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only K8-17`
  - *Exploit:* `datsu exploit --id K8-17 --marker <token>`

### K8-18 — pidfd FD-steal (seccomp unset + namespace not Restricted)

*k8s · HIGH · version/documented · triage D13*

- **Preconditions:** kernel version vulnerable to the pidfd FD-steal CVE.
- **Q1 — detect precondition:** ⚠️ inconclusive — `kernel 6.8.0-139-generic — pidfd FD-steal (CVE-2026-46333) needs a vulnerable kernel — verify against the advisory`
- **Q2 — exploit:** — N/A by design — `version/CVE precondition — detection only (cyber_gate: no live exploitation of a version-pinned component)`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only K8-18`
  - *Exploit:* `datsu exploit --id K8-18 --marker <token>`

### K8-19 — SA can create pods/exec (exec into any pod)

*k8s · HIGH · config/documented*

- **Preconditions:** A non-system ServiceAccount that can create pods/exec.
- **Q1 — detect precondition:** ✅ detected — `SA can exec into pods: datsu-arm:datsu-arm-k8-19-sa, datsu-arm:datsu-arm-k8-29-sa`
- **Q2 — exploit:** ✅ exploited — `as datsu-arm:datsu-arm-k8-19-sa — ESCAPE_K8-19_RS_lab2`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm create sa datsu-arm-k8-19-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    cat <<EOF | kubectl apply -f - >/dev/null 2>&1
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata: {name: datsu-arm-k8-19-role, namespace: datsu-arm}
    rules: [{apiGroups: [""], resources: ["pods/exec"], verbs: ["create"]}]
    EOF
    kubectl -n datsu-arm create rolebinding datsu-arm-k8-19-role-rb --role=datsu-arm-k8-19-role --serviceaccount=datsu-arm:datsu-arm-k8-19-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-19`
  - *Exploit:* `datsu exploit --id K8-19 --marker <token>`

### K8-20 — SA can create pods/attach (attach to any pod)

*k8s · HIGH · config/documented*

- **Preconditions:** A non-system ServiceAccount that can create pods/attach.
- **Q1 — detect precondition:** ✅ detected — `SA can attach to pods: datsu-arm:datsu-arm-k8-20-sa, datsu-arm:datsu-arm-k8-29-sa`
- **Q2 — exploit:** ✅ exploited — `as datsu-arm:datsu-arm-k8-20-sa — yes`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm create sa datsu-arm-k8-20-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    cat <<EOF | kubectl apply -f - >/dev/null 2>&1
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata: {name: datsu-arm-k8-20-role, namespace: datsu-arm}
    rules: [{apiGroups: [""], resources: ["pods/attach"], verbs: ["create"]}]
    EOF
    kubectl -n datsu-arm create rolebinding datsu-arm-k8-20-role-rb --role=datsu-arm-k8-20-role --serviceaccount=datsu-arm:datsu-arm-k8-20-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-20`
  - *Exploit:* `datsu exploit --id K8-20 --marker <token>`

### K8-21 — SA can read Secrets cluster-wide (get/list secrets)

*k8s · CRITICAL · config/documented*

- **Preconditions:** A non-system ServiceAccount that can get/list secrets cluster-wide.
- **Q1 — detect precondition:** ✅ detected — `SA can read secrets: datsu-arm:datsu-arm-k8-21-sa, datsu-arm:datsu-arm-k8-29-sa`
- **Q2 — exploit:** ✅ exploited — `as datsu-arm:datsu-arm-k8-21-sa — secret/datsu-arm-k809`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm create sa datsu-arm-k8-21-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    cat <<EOF | kubectl apply -f - >/dev/null 2>&1
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata: {name: datsu-arm-k8-21-role, namespace: datsu-arm}
    rules: [{apiGroups: [""], resources: ["secrets"], verbs: ["get","list"]}]
    EOF
    kubectl -n datsu-arm create rolebinding datsu-arm-k8-21-role-rb --role=datsu-arm-k8-21-role --serviceaccount=datsu-arm:datsu-arm-k8-21-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-21`
  - *Exploit:* `datsu exploit --id K8-21 --marker <token>`

### K8-22 — SA can create serviceaccounts/token (TokenRequest)

*k8s · HIGH · config/documented*

- **Preconditions:** A non-system ServiceAccount that can create serviceaccounts/token.
- **Q1 — detect precondition:** ✅ detected — `SA can mint SA tokens: datsu-arm:datsu-arm-k8-22-sa, datsu-arm:datsu-arm-k8-29-sa`
- **Q2 — exploit:** ❌ FAILED — `as datsu-arm:datsu-arm-k8-22-sa — error: failed to`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm create sa datsu-arm-k8-22-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    cat <<EOF | kubectl apply -f - >/dev/null 2>&1
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata: {name: datsu-arm-k8-22-role, namespace: datsu-arm}
    rules: [{apiGroups: [""], resources: ["serviceaccounts/token"], verbs: ["create"]}]
    EOF
    kubectl -n datsu-arm create rolebinding datsu-arm-k8-22-role-rb --role=datsu-arm-k8-22-role --serviceaccount=datsu-arm:datsu-arm-k8-22-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-22`
  - *Exploit:* `datsu exploit --id K8-22 --marker <token>`

### K8-23 — SA granted impersonate (users/groups/serviceaccounts)

*k8s · CRITICAL · config/documented*

- **Preconditions:** A non-system ServiceAccount granted impersonate.
- **Q1 — detect precondition:** ✅ detected — `SA can impersonate: datsu-arm:datsu-arm-k8-23-sa, datsu-arm:datsu-arm-k8-29-sa`
- **Q2 — exploit:** ❌ FAILED — `as datsu-arm:datsu-arm-k8-23-sa — Error from server (Forbidden): secrets is forbidden: User "system:masters" cannot list resource "secrets" in API group "" in t`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm create sa datsu-arm-k8-23-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    cat <<EOF | kubectl apply -f - >/dev/null 2>&1
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata: {name: datsu-arm-k8-23-role, namespace: datsu-arm}
    rules: [{apiGroups: [""], resources: ["users","groups","serviceaccounts"], verbs: ["impersonate"]}]
    EOF
    kubectl -n datsu-arm create rolebinding datsu-arm-k8-23-role-rb --role=datsu-arm-k8-23-role --serviceaccount=datsu-arm:datsu-arm-k8-23-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-23`
  - *Exploit:* `datsu exploit --id K8-23 --marker <token>`

### K8-24 — SA can approve certificatesigningrequests

*k8s · CRITICAL · config/documented*

- **Preconditions:** A non-system ServiceAccount that can approve certificatesigningrequests.
- **Q1 — detect precondition:** ✅ detected — `SA can approve CSRs: datsu-arm:datsu-arm-k8-24-sa, datsu-arm:datsu-arm-k8-29-sa`
- **Q2 — exploit:** ✅ exploited — `as datsu-arm:datsu-arm-k8-24-sa — Warning: resource 'certificatesigningrequests' is not namespace scoped in group 'certificates.k8s.io'`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm create sa datsu-arm-k8-24-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    cat <<EOF | kubectl apply -f - >/dev/null 2>&1
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata: {name: datsu-arm-k8-24-role, namespace: datsu-arm}
    rules: [{apiGroups: ["certificates.k8s.io"], resources: ["certificatesigningrequests","certificatesigningrequests/approval"], verbs: ["create","approve"]}]
    EOF
    kubectl -n datsu-arm create rolebinding datsu-arm-k8-24-role-rb --role=datsu-arm-k8-24-role --serviceaccount=datsu-arm:datsu-arm-k8-24-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-24`
  - *Exploit:* `datsu exploit --id K8-24 --marker <token>`

### K8-25 — SA can create pod-spawning workloads (Deployments/Jobs/…)

*k8s · CRITICAL · config/documented*

- **Preconditions:** A non-system ServiceAccount that can create pod-spawning workloads.
- **Q1 — detect precondition:** ✅ detected — `SA can create workloads: datsu-arm:datsu-arm-k8-25-sa, datsu-arm:datsu-arm-k8-29-sa`
- **Q2 — exploit:** ✅ exploited — `as datsu-arm:datsu-arm-k8-25-sa — deployment.apps/datsu-x-dep created`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm create sa datsu-arm-k8-25-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    cat <<EOF | kubectl apply -f - >/dev/null 2>&1
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata: {name: datsu-arm-k8-25-role, namespace: datsu-arm}
    rules: [{apiGroups: ["apps","batch"], resources: ["deployments","daemonsets","jobs","cronjobs","statefulsets"], verbs: ["create"]}]
    EOF
    kubectl -n datsu-arm create rolebinding datsu-arm-k8-25-role-rb --role=datsu-arm-k8-25-role --serviceaccount=datsu-arm:datsu-arm-k8-25-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-25`
  - *Exploit:* `datsu exploit --id K8-25 --marker <token>`

### K8-26 — SA granted nodes/proxy (reach each node's kubelet)

*k8s · CRITICAL · config/documented*

- **Preconditions:** A non-system ServiceAccount granted nodes/proxy.
- **Q1 — detect precondition:** ✅ detected — `SA can proxy to nodes: datsu-arm:datsu-arm-k8-26-sa, datsu-arm:datsu-arm-k8-29-sa`
- **Q2 — exploit:** ✅ exploited — `as datsu-arm:datsu-arm-k8-26-sa — ok`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm create sa datsu-arm-k8-26-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    cat <<EOF | kubectl apply -f - >/dev/null 2>&1
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata: {name: datsu-arm-k8-26-role, namespace: datsu-arm}
    rules: [{apiGroups: [""], resources: ["nodes/proxy"], verbs: ["get","create"]}]
    EOF
    kubectl -n datsu-arm create rolebinding datsu-arm-k8-26-role-rb --role=datsu-arm-k8-26-role --serviceaccount=datsu-arm:datsu-arm-k8-26-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-26`
  - *Exploit:* `datsu exploit --id K8-26 --marker <token>`

### K8-27 — SA can create mutatingwebhookconfigurations

*k8s · CRITICAL · config/documented*

- **Preconditions:** A non-system ServiceAccount that can create mutatingwebhookconfigurations.
- **Q1 — detect precondition:** ✅ detected — `SA can create mutating webhooks: datsu-arm:datsu-arm-k8-27-sa, datsu-arm:datsu-arm-k8-29-sa`
- **Q2 — exploit:** ✅ exploited — `as datsu-arm:datsu-arm-k8-27-sa — Error from server (NotFound): mutatingwebhookconfigurations.admissionregistration.k8s.io "datsu-x-mwh" not found`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm create sa datsu-arm-k8-27-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    cat <<EOF | kubectl apply -f - >/dev/null 2>&1
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata: {name: datsu-arm-k8-27-role, namespace: datsu-arm}
    rules: [{apiGroups: ["admissionregistration.k8s.io"], resources: ["mutatingwebhookconfigurations"], verbs: ["create"]}]
    EOF
    kubectl -n datsu-arm create rolebinding datsu-arm-k8-27-role-rb --role=datsu-arm-k8-27-role --serviceaccount=datsu-arm:datsu-arm-k8-27-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-27`
  - *Exploit:* `datsu exploit --id K8-27 --marker <token>`

### K8-28 — SA can create validatingwebhookconfigurations

*k8s · HIGH · config/documented*

- **Preconditions:** A non-system ServiceAccount that can create validatingwebhookconfigurations.
- **Q1 — detect precondition:** ✅ detected — `SA can create validating webhooks: datsu-arm:datsu-arm-k8-28-sa, datsu-arm:datsu-arm-k8-29-sa`
- **Q2 — exploit:** ✅ exploited — `as datsu-arm:datsu-arm-k8-28-sa — Error from server (NotFound): validatingwebhookconfigurations.admissionregistration.k8s.io "datsu-x-vwh" not found`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm create sa datsu-arm-k8-28-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    cat <<EOF | kubectl apply -f - >/dev/null 2>&1
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata: {name: datsu-arm-k8-28-role, namespace: datsu-arm}
    rules: [{apiGroups: ["admissionregistration.k8s.io"], resources: ["validatingwebhookconfigurations"], verbs: ["create"]}]
    EOF
    kubectl -n datsu-arm create rolebinding datsu-arm-k8-28-role-rb --role=datsu-arm-k8-28-role --serviceaccount=datsu-arm:datsu-arm-k8-28-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-28`
  - *Exploit:* `datsu exploit --id K8-28 --marker <token>`

### K8-29 — SA bound to a wildcard rule (apiGroups/resources/verbs *)

*k8s · CRITICAL · config/documented*

- **Preconditions:** A non-system ServiceAccount bound to a wildcard RBAC rule (*/*/*).
- **Q1 — detect precondition:** ✅ detected — `SA has wildcard RBAC: datsu-arm:datsu-arm-k8-29-sa`
- **Q2 — exploit:** ✅ exploited — `as datsu-arm:datsu-arm-k8-29-sa — secret/datsu-arm-k809`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm create sa datsu-arm-k8-29-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    cat <<EOF | kubectl apply -f - >/dev/null 2>&1
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata: {name: datsu-arm-k8-29-role, namespace: datsu-arm}
    rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
    EOF
    kubectl -n datsu-arm create rolebinding datsu-arm-k8-29-role-rb --role=datsu-arm-k8-29-role --serviceaccount=datsu-arm:datsu-arm-k8-29-sa --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-29`
  - *Exploit:* `datsu exploit --id K8-29 --marker <token>`

### K8-30 — kubelet read-only port :10255 exposed

*k8s · HIGH · config/documented*

- **Preconditions:** kubelet read-only port :10255 enabled (kubelet reconfigure — not auto-armed).
- **Q1 — detect precondition:** ✅ detected — `kubelet ro-port 10255 -> 200`
- **Q2 — exploit:** ✅ exploited — `unauth kubelet 10255 /pods (ESCAPE_K8-30_RS_lab2): {"kind":"PodList","apiVersion":"v1","metadata":{},"items":[{"metadata":{"name":"datsu-arm-k8-45","namespace":`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    (control-plane / host-state — armed by the lab setup)
    ```
  - *Detect:* `datsu detect --only K8-30`
  - *Exploit:* `datsu exploit --id K8-30 --marker <token>`

### K8-31 — network-reachable etcd (2379/2380) without client-cert auth

*k8s · CRITICAL · config/documented*

- **Preconditions:** etcd reachable on 2379/2380 without client-cert auth (not auto-armed).
- **Q1 — detect precondition:** — absent (arm to test) — `etcd 2379 https=000 http=000 (200 w/o client cert = unauth)`
- **Q2 — exploit:** ❌ FAILED — `etcd reachable without a client cert (ESCAPE_K8-31_RS_lab2):`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only K8-31`
  - *Exploit:* `datsu exploit --id K8-31 --marker <token>`

### K8-32 — kubelet authorization-mode=AlwaysAllow

*k8s · CRITICAL · config/precondition*

- **Preconditions:** kubelet authorization-mode=AlwaysAllow (kubelet reconfigure — not auto-armed).
- **Q1 — detect precondition:** ✅ detected — `kubelet authorization-mode=AlwaysAllow configured`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — kubelet authorizes every request (even with any node credential) -> /exec on any pod. Distinct from K8-06 anon-auth.`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    (control-plane / host-state — armed by the lab setup)
    ```
  - *Detect:* `datsu detect --only K8-32`
  - *Exploit:* `datsu exploit --id K8-32 --marker <token>`

### K8-33 — kubeadm static-pod manifests dir writable (/etc/kubernetes/manifests)

*k8s · CRITICAL · config/precondition*

- **Preconditions:** kubeadm /etc/kubernetes/manifests writable (kubeadm-only path — host-state).
- **Q1 — detect precondition:** ✅ detected — `/etc/kubernetes/manifests 777`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — kubelet runs any manifest dropped here as a static pod — as root on the node (kubeadm path; K8-10 is the k3s addon path).`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    (control-plane / host-state — armed by the lab setup)
    ```
  - *Detect:* `datsu detect --only K8-33`
  - *Exploit:* `datsu exploit --id K8-33 --marker <token>`

### K8-34 — pod hostPath-mounts a sensitive node path (socket / kubelet / pki / proc)

*k8s · CRITICAL · config/precondition*

- **Preconditions:** A pod hostPath-mounting a sensitive node path (container socket / kubelet / pki / proc).
- **Q1 — detect precondition:** ✅ detected — `datsu-arm/datsu-arm-k8-34`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — a hostPath other than '/' (container-runtime socket, /var/lib/kubelet, /etc/kubernetes, /proc, /dev) is an equal-or-worse node compromise; `
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm run datsu-arm-k8-34 --image=alpine --restart=Never --overrides='{"spec":{"containers":[{"name":"c","image":"alpine","command":["sleep","600"],"volumeMounts":[{"name":"h","mountPath":"/host"}]}],"volumes":[{"name":"h","hostPath":{"path":"/var/lib/kubelet"}}]}}' --command -- sleep 600 >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-34`
  - *Exploit:* `datsu exploit --id K8-34 --marker <token>`

### K8-35 — kubeadm admin.conf or cluster CA key group/world-readable

*k8s · CRITICAL · config/precondition*

- **Preconditions:** kubeadm admin.conf or CA key group/world-readable (host-state — not auto-armed).
- **Q1 — detect precondition:** ✅ detected — `/etc/kubernetes/admin.conf 644 readable`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — /etc/kubernetes/admin.conf is cluster-admin; /etc/kubernetes/pki/ca.key mints any cert. K8-11 is the k3s kubeconfig only.`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    (control-plane / host-state — armed by the lab setup)
    ```
  - *Detect:* `datsu detect --only K8-35`
  - *Exploit:* `datsu exploit --id K8-35 --marker <token>`

### K8-36 — pod requests dangerous Linux capabilities (securityContext.capabilities.add)

*k8s · HIGH · config/precondition*

- **Preconditions:** A pod adding a dangerous Linux capability via securityContext.capabilities.add.
- **Q1 — detect precondition:** ✅ detected — `datsu-arm/datsu-arm-k8-36`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — a non-privileged pod adding SYS_ADMIN/SYS_MODULE/SYS_PTRACE/BPF/… — the k8s-side analog of DK-03..06 (no existing K8 check).`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm run datsu-arm-k8-36 --image=alpine --restart=Never --overrides='{"spec":{"containers":[{"name":"c","image":"alpine","command":["sleep","600"],"securityContext":{"capabilities":{"add":["SYS_ADMIN"]}}}]}}' --command -- sleep 600 >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-36`
  - *Exploit:* `datsu exploit --id K8-36 --marker <token>`

### K8-37 — legacy long-lived ServiceAccount-token Secrets present

*k8s · HIGH · config/precondition*

- **Preconditions:** A legacy long-lived ServiceAccount-token Secret.
- **Q1 — detect precondition:** ✅ detected — `secret/datsu-arm-k837`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — never-expiring SA tokens (type kubernetes.io/service-account-token) are stealable, replayable credentials; prefer bound TokenRequest tokens`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm create sa datsu-arm-sa837 --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1; cat <<EOF | kubectl apply -f - >/dev/null 2>&1
    apiVersion: v1
    kind: Secret
    metadata: {name: datsu-arm-k837, namespace: datsu-arm, annotations: {kubernetes.io/service-account.name: datsu-arm-sa837}}
    type: kubernetes.io/service-account-token
    EOF
    ```
  - *Detect:* `datsu detect --only K8-37`
  - *Exploit:* `datsu exploit --id K8-37 --marker <token>`

### K8-38 — no cluster-wide admission guardrail (no namespace enforces PodSecurity restricted)

*k8s · MEDIUM · config/precondition*

- **Preconditions:** No namespace enforces PodSecurity restricted and no admission webhook (cluster posture).
- **Q1 — detect precondition:** ✅ detected — `no non-system namespace enforces PodSecurity restricted`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — without PSA enforce=restricted anywhere (and no admission webhook), a privileged/hostPath pod is admitted everywhere. Broader than K8-07 (s`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only K8-38`
  - *Exploit:* `datsu exploit --id K8-38 --marker <token>`

### K8-39 — ServiceAccount token auto-mounted into pods

*k8s · MEDIUM · config/precondition*

- **Preconditions:** A pod on a non-default ServiceAccount with the token auto-mounted.
- **Q1 — detect precondition:** ✅ detected — `datsu-arm/datsu-arm-k839`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — automountServiceAccountToken not disabled — a compromised pod gets a live API token by default (posture).`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm create sa datsu-arm-sa839 --dry-run=client -o yaml | kubectl apply -f - >/dev/null 2>&1; kubectl -n datsu-arm run datsu-arm-k839 --image=alpine --restart=Never --overrides='{"spec":{"serviceAccountName":"datsu-arm-sa839"}}' --command -- sleep 600 >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-39`
  - *Exploit:* `datsu exploit --id K8-39 --marker <token>`

### K8-40 — no default-deny NetworkPolicy (flat pod network)

*k8s · MEDIUM · config/precondition*

- **Preconditions:** No NetworkPolicy exists cluster-wide (cluster posture).
- **Q1 — detect precondition:** ✅ detected — `NetworkPolicies cluster-wide: 0`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — zero NetworkPolicies -> any pod reaches every pod, the API server, and node-local services (lateral movement).`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only K8-40`
  - *Exploit:* `datsu exploit --id K8-40 --marker <token>`

### K8-41 — pod with shareProcessNamespace: true

*k8s · MEDIUM · config/precondition*

- **Preconditions:** A pod with shareProcessNamespace: true.
- **Q1 — detect precondition:** ✅ detected — `datsu-arm/datsu-arm-k8-41`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — containers in the pod share one PID ns — a sidecar can read another container's /proc memory and fds.`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm run datsu-arm-k8-41 --image=alpine --restart=Never --overrides='{"spec":{"shareProcessNamespace":true,"containers":[{"name":"c","image":"alpine","command":["sleep","600"]}]}}' --command -- sleep 600 >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-41`
  - *Exploit:* `datsu exploit --id K8-41 --marker <token>`

### K8-42 — pod runs as root (no runAsNonRoot / runAsUser 0)

*k8s · MEDIUM · config/precondition*

- **Preconditions:** A pod running as root (no runAsNonRoot).
- **Q1 — detect precondition:** ✅ detected — `datsu-arm/datsu-arm-k8-34`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — neither pod nor container sets runAsNonRoot:true — processes run as uid 0, amplifying any other weakness (posture).`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm run datsu-arm-k8-42 --image=alpine --restart=Never --overrides='{"spec":{"containers":[{"name":"c","image":"alpine","command":["sleep","600"]}]}}' --command -- sleep 600 >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-42`
  - *Exploit:* `datsu exploit --id K8-42 --marker <token>`

### K8-43 — pod binds a hostPort

*k8s · MEDIUM · config/precondition*

- **Preconditions:** A pod binding a hostPort.
- **Q1 — detect precondition:** ✅ detected — `datsu-arm/datsu-arm-k8-43`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — a hostPort publishes the container on the node's network, bypassing Service/NetworkPolicy and exposing it on the node IP.`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm run datsu-arm-k8-43 --image=alpine --restart=Never --overrides='{"spec":{"containers":[{"name":"c","image":"alpine","command":["sleep","600"],"ports":[{"containerPort":9999,"hostPort":39999}]}]}}' --command -- sleep 600 >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-43`
  - *Exploit:* `datsu exploit --id K8-43 --marker <token>`

### K8-44 — kube-apiserver proxy/upgrade privilege escalation

*k8s · CRITICAL · version/documented · CVE-2018-1002105*

- **Preconditions:** kube-apiserver < 1.10.11/1.11.5/1.12.3 (CVE-2018-1002105).
- **Q1 — detect precondition:** — absent (arm to test) — `kube-apiserver: 1.36.5 (fixed >= 1.12.3)`
- **Q2 — exploit:** — N/A by design — `version/CVE precondition — detection only (cyber_gate: no live exploitation of a version-pinned component)`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only K8-44`
  - *Exploit:* `datsu exploit --id K8-44 --marker <token>`

### K8-45 — gitRepo volume in use (deprecated; kubelet runs git clone as root)

*k8s · HIGH · config/precondition · CVE-2024-10220*

- **Preconditions:** A pod using a (deprecated) gitRepo volume.
- **Q1 — detect precondition:** ✅ detected — `datsu-arm/datsu-arm-k8-45`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — CVE-2024-10220 — a gitRepo volume lets a crafted repo run hooks as root on the node. Any gitRepo-volume pod is a finding.`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm run datsu-arm-k8-45 --image=alpine --restart=Never --overrides='{"spec":{"containers":[{"name":"c","image":"alpine","command":["sleep","600"],"volumeMounts":[{"name":"g","mountPath":"/repo"}]}],"volumes":[{"name":"g","gitRepo":{"repository":"https://example.com/x.git"}}]}}' --command -- sleep 600 >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-45`
  - *Exploit:* `datsu exploit --id K8-45 --marker <token>`

### K8-46 — kubelet subPath symlink-swap race

*k8s · HIGH · version/documented · CVE-2021-25741*

- **Preconditions:** kubelet < 1.19.16/1.20.11/1.21.5 (CVE-2021-25741 subPath).
- **Q1 — detect precondition:** — absent (arm to test) — `kubelet: 1.36.5 (fixed >= 1.22.0)`
- **Q2 — exploit:** — N/A by design — `version/CVE precondition — detection only (cyber_gate: no live exploitation of a version-pinned component)`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only K8-46`
  - *Exploit:* `datsu exploit --id K8-46 --marker <token>`

### K8-47 — ingress-nginx IngressNightmare unauthenticated RCE

*k8s · CRITICAL · version/documented · CVE-2025-1974*

- **Preconditions:** ingress-nginx controller < 1.11.5 / 1.12.1 (IngressNightmare).
- **Q1 — detect precondition:** — absent (arm to test) — `ingress-nginx controller not detected`
- **Q2 — exploit:** — N/A by design — `version/CVE precondition — detection only (cyber_gate: no live exploitation of a version-pinned component)`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only K8-47`
  - *Exploit:* `datsu exploit --id K8-47 --marker <token>`

### K8-48 — CRI-O cr8escape (pod-supplied sysctl -> host command exec)

*k8s · CRITICAL · version/documented · CVE-2022-0811*

- **Preconditions:** CRI-O < 1.23.2 (cr8escape CVE-2022-0811).
- **Q1 — detect precondition:** ⚠️ inconclusive — `crio not found on PATH`
- **Q2 — exploit:** — N/A by design — `version/CVE precondition — detection only (cyber_gate: no live exploitation of a version-pinned component)`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only K8-48`
  - *Exploit:* `datsu exploit --id K8-48 --marker <token>`

### K8-49 — kernel fs_context heap overflow (LPE from a pod)

*k8s · HIGH · version/documented · CVE-2022-0185*

- **Preconditions:** kernel < ~5.17 reachable from an unprivileged pod (CVE-2022-0185).
- **Q1 — detect precondition:** — absent (arm to test) — `kernel (CVE-2022-0185 fs_context): 6.8.0 (fixed >= 5.17)`
- **Q2 — exploit:** — N/A by design — `version/CVE precondition — detection only (cyber_gate: no live exploitation of a version-pinned component)`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only K8-49`
  - *Exploit:* `datsu exploit --id K8-49 --marker <token>`

### K8-50 — cloud IMDS credential theft reachable from the node/pods (AWS/GCP/Azure)

*k8s · CRITICAL · config/documented*

- **Preconditions:** A cloud IMDS (AWS/GCP/Azure) reachable from pods — cloud clusters only.
- **Q1 — detect precondition:** — absent (arm to test) — `IMDS aws=000 gcp=000 azure=000`
- **Q2 — exploit:** ❌ FAILED — `cloud creds (ESCAPE_K8-50_RS_lab2): aws-role=none gcp-token=`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only K8-50`
  - *Exploit:* `datsu exploit --id K8-50 --marker <token>`

### K8-51 — imagePullSecrets / dockerconfigjson present (registry creds)

*k8s · MEDIUM · config/precondition*

- **Preconditions:** A dockerconfigjson imagePullSecret present (ambient).
- **Q1 — detect precondition:** — absent (arm to test)
- **Q2 — exploit:** — N/A by design — `not auto-exploited — pods/SAs referencing a dockerconfigjson secret — a compromised pod can read and reuse the registry credential.`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only K8-51`
  - *Exploit:* `datsu exploit --id K8-51 --marker <token>`

### K8-52 — secrets embedded in ConfigMaps / container env literals

*k8s · HIGH · config/precondition*

- **Preconditions:** Credential-looking values in a ConfigMap or container env (ambient).
- **Q1 — detect precondition:** — absent (arm to test)
- **Q2 — exploit:** — N/A by design — `not auto-exploited — credential-looking keys with literal values in ConfigMaps (or container env .value) — unencrypted, broadly readable. Heuristic.`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only K8-52`
  - *Exploit:* `datsu exploit --id K8-52 --marker <token>`

### K8-53 — unpinned / mutable image references (:latest or no digest)

*k8s · MEDIUM · config/precondition*

- **Preconditions:** A pod running an unpinned :latest image.
- **Q1 — detect precondition:** ✅ detected — `datsu-arm/datsu-arm-k8-34`
- **Q2 — exploit:** — N/A by design — `not auto-exploited — images by :latest or a bare tag (no @sha256 digest) are mutable — a registry compromise silently swaps the running code (supply-chain).`
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    kubectl create ns datsu-arm >/dev/null 2>&1; kubectl -n datsu-arm run datsu-arm-k853 --image=alpine:latest --restart=Never --command -- sleep 600 >/dev/null 2>&1
    ```
  - *Detect:* `datsu detect --only K8-53`
  - *Exploit:* `datsu exploit --id K8-53 --marker <token>`

### K8-54 — legacy Helm v2 Tiller in-cluster (unauthenticated :44134)

*k8s · CRITICAL · config/documented*

- **Preconditions:** Legacy Helm v2 Tiller deployed in-cluster (not auto-armed).
- **Q1 — detect precondition:** ✅ detected — `tiller objects: 3`
- **Q2 — exploit:** ✅ exploited — `Helm v2 Tiller present (ESCAPE_K8-54_RS_lab2): kube-system   service/tiller-deploy    ClusterIP      10.43.37.113    <none>          44134/TCP                  `
- **Reproduce:**
  - *Arm the precondition:*
    ```sh
    (control-plane / host-state — armed by the lab setup)
    ```
  - *Detect:* `datsu detect --only K8-54`
  - *Exploit:* `datsu exploit --id K8-54 --marker <token>`

### K8-NA — cloud IMDS (169.254.169.254) — not present on Proxmox

*k8s · INFO · n-a/documented*

- **Preconditions:** A cloud instance-metadata service present — absent on Proxmox (expected n-a).
- **Q1 — detect precondition:** — absent (arm to test) — `IMDS -> 000`
- **Q2 — exploit:** — N/A by design — `not applicable on this platform`
- **Reproduce:**
  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.
  - *Detect:* `datsu detect --only K8-NA`
  - *Exploit:* `datsu exploit --id K8-NA --marker <token>`

---

Generated by `datsu validate`. Author: d3vn0mi (RavenSec).