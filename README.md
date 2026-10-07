# datsu 脱獄

**Datsu** (*datsugoku*, 脱獄 — "jailbreak") is a single, consolidated tool that **detects** Docker &
Kubernetes container-escape conditions on a node (read-only) and, when you authorize it, **exploits**
them to prove the breakout. 37 scenarios — 18 Docker/host, 19 Kubernetes — covering privileged
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

Run `datsu list` for the live catalogue. Summary:

### Docker / host
| ID | Vector | Sev | Exploit |
|----|--------|-----|---------|
| DK-01 | privileged container (`--privileged`) | CRITICAL | concrete |
| DK-02 | docker.sock bind-mounted into a container | CRITICAL | documented |
| DK-03 | SYS_ADMIN + cgroup v1 release_agent | HIGH | precondition |
| DK-04 | SYS_MODULE capability | HIGH | precondition |
| DK-05 | DAC_READ_SEARCH capability | HIGH | precondition |
| DK-06 | SYS_PTRACE + hostPID | HIGH | precondition |
| DK-07 | sensitive bind mount (`-v /:/host`) | HIGH | concrete |
| DK-08 | host device exposed (`--device`) | HIGH | documented |
| DK-09 | host network + IPC namespaces | HIGH | documented |
| DK-10 | seccomp unconfined | HIGH | documented |
| DK-11 | no-new-privs off + setuid-root helper | HIGH | concrete |
| DK-12 | dockerd exposed on tcp/2375 | CRITICAL | documented |
| DK-13 | lab user in the docker group | HIGH | concrete |
| DK-14 | rshared bind-propagation mount | MEDIUM | precondition |
| DK-15 | core_pattern redirected to a handler | HIGH | documented |
| DK-16 | runc Leaky Vessels (CVE-2024-21626) | HIGH | version |
| DK-17 | runc 2025 maskedPaths/procfs race | HIGH | version |
| DK-18 | kernel LPE from an unprivileged container | HIGH | version |

### Kubernetes
| ID | Vector | Sev | Exploit |
|----|--------|-----|---------|
| K8-01 | SA bound to a Role granting create pods | CRITICAL | documented |
| K8-02 | privileged pod | CRITICAL | concrete |
| K8-03 | hostPath mount of `/` | CRITICAL | concrete |
| K8-04 | hostPID/hostNetwork/hostIPC pod | HIGH | documented |
| K8-05 | privileged DaemonSet | HIGH | documented |
| K8-06 | kubelet :10250 anonymous-auth | HIGH | documented |
| K8-07 | namespace without PSA enforce=restricted | HIGH | documented |
| K8-08 | NET_RAW ARP/DNS spoof between co-located pods | MEDIUM | documented |
| K8-09 | embedded etcd read bypassing RBAC | CRITICAL | documented |
| K8-10 | static-pod manifest directory writable | HIGH | documented |
| K8-11 | node admin kubeconfig group/world-readable | HIGH | documented |
| K8-12 | apiserver anonymous-auth | CRITICAL | documented |
| K8-13 | system:anonymous bound to a ClusterRole | CRITICAL | concrete |
| K8-14 | SA can create PersistentVolumes (hostPath) | HIGH | documented |
| K8-15 | SA can create pods/ephemeralcontainers | HIGH | documented |
| K8-16 | ClusterRole grants escalate/bind | HIGH | documented |
| K8-17 | Secrets stored unencrypted in etcd | MEDIUM | documented |
| K8-18 | pidfd FD-steal (seccomp unset + ns) | HIGH | version |
| K8-NA | cloud IMDS (169.254.169.254) | INFO | n-a |

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
