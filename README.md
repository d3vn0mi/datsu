# datsu 脱獄

**Datsu** (*datsugoku*, 脱獄 — "jailbreak") is a single, consolidated tool that **detects** Docker &
Kubernetes container-escape conditions on a node (read-only) and, when you authorize it, **exploits**
them to prove the breakout. 93 scenarios — 38 Docker/host, 55 Kubernetes — covering privileged
containers, dangerous capabilities, host mounts and namespaces, exposed daemons, kubelet/apiserver
anonymous auth, dangerous RBAC, writable control-plane paths, and cleartext etcd.

It is the operational companion to the RavenSec `docker-kube-escapes` validation engagement: the
same catalogue, turned into a drop-on-a-node CLI.

> **Authorized use only.** Detection is read-only. Exploitation changes node state and is intended
> for a system you own or are explicitly engaged to test — an isolated, disposable lab. The
> exploiter refuses to run without an explicit `--marker`, and never performs novel weaponization
> (see [Safety](#safety--rules-of-engagement)).

## Install

Python 3.9+. No Python dependencies — the checks shell out to tools already on a node.

```bash
git clone https://github.com/d3vn0mi/datsu
cd datsu
pip install -e .          # provides the `datsu` command
# or run without installing:
python3 -m datsu --help
```

At runtime the node needs the usual admin tooling, used only where a scenario applies:
`docker`, `kubectl`, `jq`, `curl`, `ss`/`netstat`. Missing tools are reported as `UNKNOWN`
(inconclusive), never a crash.

## Usage

### List the catalogue
```bash
datsu list                 # or: datsu list --json
```

### Detect — read-only audit
```bash
datsu detect                       # every scenario
datsu detect --class k8s           # Kubernetes only
datsu detect --only DK-02 K8-09    # specific ids
datsu detect --json                # machine-readable
datsu detect --fail-on-present     # exit 1 if any condition present (CI gate)
```

```text
  [+] DK-02  PRESENT  docker.sock bind-mounted into a container
            └ /esc-dk-02
  [-] DK-07  ABSENT   sensitive bind mount (-v /:/host)
  [+] K8-11  PRESENT  node admin kubeconfig left group/world-readable
            └ /etc/rancher/k3s/k3s.yaml 644
  [?] DK-16  UNKNOWN  runc Leaky Vessels (fd leak via WORKDIR trick)
            └ runc binary not found on PATH

  3 present, 1 inconclusive, ... absent
```

Each verdict: `PRESENT` (condition exists), `ABSENT` (clean), `UNKNOWN` (a required tool was
missing — inconclusive, not clean).

### Exploit — gated, marker-stamped
```bash
datsu exploit --id K8-09 --marker RS_$(date +%s)   # one condition
datsu exploit --all      --marker RS_demo          # every detected, exploitable condition
```

The exploiter sets up a **disposable, marker-stamped** demonstrator for the scenario (e.g. a short-
lived `esc-x-*` container/pod, or a one-shot command against an ambient host condition), proves the
breakout by verifying its sentinel `ESCAPE_<ID>_<marker>`, then cleans up. `--all` first runs
detection and only attempts conditions that are actually **present** and **exploitable**.

```text
  [+] K8-09  SUCCESS      embedded etcd read bypassing RBAC
            └ Secret canary read in cleartext from on-disk etcd (ESCAPE_K8-09_RS_demo)
  [.] K8-06  SKIPPED      kubelet :10250 anonymous-auth
            └ not auto-exploited — anon kubelet not present
  [x] K8-10  FAILED       static-pod manifest directory writable

  1 proven, 1 failed, 1 skipped/inconclusive
```

## How it works

Every scenario carries two halves:

- **Detector** — a read-only check that answers *is this condition present on the node now?*,
  generalized to scan the node's whole current state (any container with a dangerous flag, any SA
  bound to a dangerous grant, the node's kubelet/apiserver/etcd/kubeconfig posture). Never changes
  state.
- **Exploiter** — the documented breakout for that condition, bounded and marker-stamped, so a run
  leaves a verifiable sentinel and nothing else.

Each exploit is tagged with a **confidence** so you know what you are running:

| Confidence | Meaning |
|---|---|
| `concrete` | a bounded, single-technique escape proven in the source engagement |
| `documented` | a public, documented technique, implemented as a bounded one-shot here |
| `precondition` | **detection only** — the escape needs offline tooling or is a multi-step race with no safe one-shot, so the tool detects the condition but does not auto-exploit it (cyber_gate) |

`version` scenarios (runc/kernel CVE preconditions) and the one `n-a` scenario are detect-only by
design and never exploited.

Internals: `datsu/scenarios.py` is the registry (one `Scenario` per row); `datsu/context.py` is the
single execution choke point (every command runs through `Context.sh`, with dry-run and timeouts);
`datsu/model.py` defines the model; `datsu/cli.py` is the CLI.

## Scenario catalogue

Run `datsu list` for the live catalogue (93 scenarios: 38 Docker/host, 55 Kubernetes).

### Docker / host
| ID | Vector | Sev | Exploit | CVE |
|----|--------|-----|---------|-----|
| DK-01 | privileged container (docker run --privileged) | CRITICAL | concrete |  |
| DK-02 | docker.sock bind-mounted into a container | CRITICAL | documented |  |
| DK-03 | SYS_ADMIN + cgroup v1 release_agent breakout | HIGH | precondition |  |
| DK-04 | SYS_MODULE capability | HIGH | precondition |  |
| DK-05 | DAC_READ_SEARCH capability | HIGH | precondition |  |
| DK-06 | SYS_PTRACE + hostPID | HIGH | precondition |  |
| DK-07 | sensitive bind mount (-v /:/host) | HIGH | concrete |  |
| DK-08 | host device exposed (--device or /dev bind) | HIGH | documented |  |
| DK-09 | host network + IPC namespaces | HIGH | documented |  |
| DK-10 | seccomp unconfined | HIGH | documented |  |
| DK-11 | no-new-privs off + setuid-root helper | HIGH | concrete |  |
| DK-12 | dockerd exposed on tcp/2375 | CRITICAL | documented |  |
| DK-13 | lab user in the docker group | HIGH | concrete |  |
| DK-14 | rshared bind-propagation mount | MEDIUM | precondition |  |
| DK-15 | core_pattern redirected to a handler | HIGH | documented |  |
| DK-16 | runc Leaky Vessels (fd leak via WORKDIR trick) | HIGH | version | CVE-2024-21626 |
| DK-17 | runc 2025 maskedPaths/procfs race family | HIGH | version |  |
| DK-18 | kernel LPE from an unprivileged container | HIGH | version |  |
| DK-19 | runc /proc/self/exe host-binary overwrite | HIGH | version | CVE-2019-5736 |
| DK-20 | BuildKit Leaky Vessels build-time escapes | CRITICAL | version | CVE-2024-23651 |
| DK-21 | runc symlink-exchange mount-destination race | HIGH | version | CVE-2021-30465 |
| DK-22 | containerd-shim abstract-socket exposure | MEDIUM | version | CVE-2020-15257 |
| DK-23 | docker cp TOCTOU symlink directory traversal | HIGH | version | CVE-2018-15664 |
| DK-24 | docker cp libnss chroot library injection | CRITICAL | version | CVE-2019-14271 |
| DK-25 | cgroup v1 release_agent escape without CAP_SYS_ADMIN | HIGH | version | CVE-2022-0492 |
| DK-26 | Docker Engine AuthZ plugin bypass (zero-length body) | CRITICAL | version | CVE-2024-41110 |
| DK-27 | CAP_BPF / CAP_PERFMON added | HIGH | precondition |  |
| DK-28 | CAP_SYS_RAWIO added | HIGH | precondition |  |
| DK-29 | CAP_SYS_BOOT added | HIGH | precondition |  |
| DK-30 | CAP_NET_ADMIN added | HIGH | precondition |  |
| DK-31 | CAP_CHECKPOINT_RESTORE added | HIGH | precondition |  |
| DK-32 | writable host /sys or /sys/fs/cgroup bind-mount | HIGH | documented |  |
| DK-33 | writable host /proc bind-mount / masked-paths disabled | HIGH | precondition |  |
| DK-34 | /dev/mem, /dev/kmem or /dev/port exposed | CRITICAL | precondition |  |
| DK-35 | AppArmor disabled (apparmor=unconfined) standalone | MEDIUM | precondition |  |
| DK-36 | SELinux label disabled (label:disable) | HIGH | precondition |  |
| DK-37 | containerd / BuildKit socket bind-mounted into a container | CRITICAL | precondition |  |
| DK-38 | host /lib/modules or /boot bind-mounted | HIGH | precondition |  |

### Kubernetes
| ID | Vector | Sev | Exploit | CVE |
|----|--------|-----|---------|-----|
| K8-01 | ServiceAccount bound to a Role granting create pods | CRITICAL | documented |  |
| K8-02 | privileged pod | CRITICAL | concrete |  |
| K8-03 | hostPath mount of / | CRITICAL | concrete |  |
| K8-04 | hostPID/hostNetwork/hostIPC pod | HIGH | documented |  |
| K8-05 | privileged DaemonSet | HIGH | documented |  |
| K8-06 | kubelet :10250 anonymous-auth | HIGH | documented |  |
| K8-07 | namespace without PSA enforce=restricted | HIGH | documented |  |
| K8-08 | NET_RAW ARP/DNS spoof between co-located pods | MEDIUM | documented |  |
| K8-09 | embedded etcd read bypassing RBAC | CRITICAL | documented |  |
| K8-10 | static-pod manifest directory writable | HIGH | documented |  |
| K8-11 | node admin kubeconfig left group/world-readable | HIGH | documented |  |
| K8-12 | apiserver anonymous-auth | CRITICAL | documented |  |
| K8-13 | system:anonymous bound to a ClusterRole | CRITICAL | concrete |  |
| K8-14 | ServiceAccount can create PersistentVolumes (hostPath) | HIGH | documented |  |
| K8-15 | ServiceAccount can create pods/ephemeralcontainers | HIGH | documented |  |
| K8-16 | ClusterRole grants escalate/bind | HIGH | documented |  |
| K8-17 | Secrets stored unencrypted in etcd | MEDIUM | documented |  |
| K8-18 | pidfd FD-steal (seccomp unset + namespace not Restricted) | HIGH | version |  |
| K8-19 | SA can create pods/exec (exec into any pod) | HIGH | precondition |  |
| K8-20 | SA can create pods/attach (attach to any pod) | HIGH | precondition |  |
| K8-21 | SA can read Secrets cluster-wide (get/list secrets) | CRITICAL | precondition |  |
| K8-22 | SA can create serviceaccounts/token (TokenRequest) | HIGH | precondition |  |
| K8-23 | SA granted impersonate (users/groups/serviceaccounts) | CRITICAL | precondition |  |
| K8-24 | SA can approve certificatesigningrequests | CRITICAL | precondition |  |
| K8-25 | SA can create pod-spawning workloads (Deployments/Jobs/…) | CRITICAL | precondition |  |
| K8-26 | SA granted nodes/proxy (reach each node's kubelet) | CRITICAL | precondition |  |
| K8-27 | SA can create mutatingwebhookconfigurations | CRITICAL | precondition |  |
| K8-28 | SA can create validatingwebhookconfigurations | HIGH | precondition |  |
| K8-29 | SA bound to a wildcard rule (apiGroups/resources/verbs *) | CRITICAL | precondition |  |
| K8-30 | kubelet read-only port :10255 exposed | HIGH | documented |  |
| K8-31 | network-reachable etcd (2379/2380) without client-cert auth | CRITICAL | documented |  |
| K8-32 | kubelet authorization-mode=AlwaysAllow | CRITICAL | precondition |  |
| K8-33 | kubeadm static-pod manifests dir writable (/etc/kubernetes/man | CRITICAL | precondition |  |
| K8-34 | pod hostPath-mounts a sensitive node path (socket / kubelet /  | CRITICAL | precondition |  |
| K8-35 | kubeadm admin.conf or cluster CA key group/world-readable | CRITICAL | precondition |  |
| K8-36 | pod requests dangerous Linux capabilities (securityContext.cap | HIGH | precondition |  |
| K8-37 | legacy long-lived ServiceAccount-token Secrets present | HIGH | precondition |  |
| K8-38 | no cluster-wide admission guardrail (no namespace enforces Pod | MEDIUM | precondition |  |
| K8-39 | ServiceAccount token auto-mounted into pods | MEDIUM | precondition |  |
| K8-40 | no default-deny NetworkPolicy (flat pod network) | MEDIUM | precondition |  |
| K8-41 | pod with shareProcessNamespace: true | MEDIUM | precondition |  |
| K8-42 | pod runs as root (no runAsNonRoot / runAsUser 0) | MEDIUM | precondition |  |
| K8-43 | pod binds a hostPort | MEDIUM | precondition |  |
| K8-44 | kube-apiserver proxy/upgrade privilege escalation | CRITICAL | version | CVE-2018-1002105 |
| K8-45 | gitRepo volume in use (deprecated; kubelet runs git clone as r | HIGH | precondition | CVE-2024-10220 |
| K8-46 | kubelet subPath symlink-swap race | HIGH | version | CVE-2021-25741 |
| K8-47 | ingress-nginx IngressNightmare unauthenticated RCE | CRITICAL | version | CVE-2025-1974 |
| K8-48 | CRI-O cr8escape (pod-supplied sysctl -> host command exec) | CRITICAL | version | CVE-2022-0811 |
| K8-49 | kernel fs_context heap overflow (LPE from a pod) | HIGH | version | CVE-2022-0185 |
| K8-50 | cloud IMDS credential theft reachable from the node/pods (AWS/ | CRITICAL | documented |  |
| K8-51 | imagePullSecrets / dockerconfigjson present (registry creds) | MEDIUM | precondition |  |
| K8-52 | secrets embedded in ConfigMaps / container env literals | HIGH | precondition |  |
| K8-53 | unpinned / mutable image references (:latest or no digest) | MEDIUM | precondition |  |
| K8-54 | legacy Helm v2 Tiller in-cluster (unauthenticated :44134) | CRITICAL | documented |  |
| K8-NA | cloud IMDS (169.254.169.254) — not present on Proxmox | INFO | n-a |  |

## Safety / rules of engagement

- **Detection is read-only.** It inspects containers, cluster objects, file permissions, and
  service posture; it never arms, writes, or restarts anything.
- **Exploitation is explicit.** It requires `--marker`; without one the tool refuses and prints
  the banner. Every proof artifact is stamped `ESCAPE_<ID>_<marker>` and cleaned up.
- **No novel weaponization (`cyber_gate`).** Only public, documented techniques. Conditions whose
  escape needs a compiler, a kernel-module blob, or an unbounded multi-step race are detected but
  **not** auto-exploited (`precondition`). Version/CVE scenarios are never exploited live — they
  only confirm the vulnerable-version precondition.
- Run it only against systems you own or are authorized to assess, ideally isolated and disposable.

## Development

```bash
pip install -e .
python3 -m pytest -q        # registry integrity + CLI wiring (no root / docker / kubectl needed)
```

The detectors and exploits are transcribed from the RavenSec `docker-kube-escapes` validation pack
(each scenario's arm/verify/proof) and the engagement report (the techniques that actually landed),
then generalized from "did my lab arm run" to "is this condition present on this node."

## Author

**d3vn0mi** — RavenSec.

## License

MIT — see [LICENSE](LICENSE).
