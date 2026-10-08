"""Execution context: the one place that touches the system.

Everything a scenario does — a docker inspect, a kubectl get, a curl probe, an exploit
command — goes through `Context.sh`, so the whole tool has a single, auditable choke point
for command execution, timeouts, and dry-run. `Context` also carries a few typed helpers
(tool discovery, JSON fetches, RBAC correlation) that are clearer in Python than in a wall
of jq.

Author: d3vn0mi (RavenSec)
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Optional

import re as _re

from .model import Detection, Exploitation


class Context:
    def __init__(self, dry_run: bool = False, timeout: int = 20, exploit_timeout: int = 90,
                 verbose: bool = False):
        self.dry_run = dry_run
        self.timeout = timeout
        self.exploit_timeout = exploit_timeout
        self.verbose = verbose
        self._have: dict[str, bool] = {}

    # ---- the single execution choke point ---------------------------------------------
    def sh(self, snippet: str, env: Optional[dict] = None, timeout: Optional[int] = None):
        """Run `snippet` under /bin/sh -c. Returns (returncode, combined_stdout_stderr).
        Never raises on a non-zero exit or a timeout; a timeout maps to rc 124."""
        if self.verbose:
            first = " ".join(snippet.split())[:200]
            print(f"  $ {first}")
        if self.dry_run:
            return 0, "[dry-run] not executed"
        full_env = dict(os.environ)
        if env:
            full_env.update(env)
        try:
            p = subprocess.run(["/bin/sh", "-c", snippet], capture_output=True, text=True,
                               errors="replace", env=full_env, timeout=timeout or self.timeout)
            return p.returncode, (p.stdout or "") + (p.stderr or "")
        except subprocess.TimeoutExpired as e:
            return 124, f"[timeout after {e.timeout}s] " + (e.stdout or "") + (e.stderr or "")
        except FileNotFoundError as e:
            return 127, str(e)

    # ---- tool discovery ---------------------------------------------------------------
    def have(self, tool: str) -> bool:
        if tool not in self._have:
            self._have[tool] = shutil.which(tool) is not None
        return self._have[tool]

    def require(self, *tools: str) -> Optional[str]:
        """Return a human message naming the first missing tool, or None if all present."""
        missing = [t for t in tools if not self.have(t)]
        return f"missing required tool(s): {', '.join(missing)}" if missing else None

    # ---- typed JSON fetches -----------------------------------------------------------
    def json_cmd(self, snippet: str):
        rc, out = self.sh(snippet)
        if rc != 0:
            return None
        try:
            return json.loads(out)
        except (ValueError, json.JSONDecodeError):
            return None

    def docker_containers(self):
        """List of inspect dicts for every running container (empty list if docker absent/none)."""
        if not self.have("docker"):
            return []
        data = self.json_cmd("docker ps -q | xargs -r docker inspect")
        return data if isinstance(data, list) else []

    def kubectl_json(self, args: str):
        """`kubectl get <args> -o json` parsed, or None (kubectl absent / API unreachable)."""
        if not self.have("kubectl"):
            return None
        return self.json_cmd(f"kubectl get {args} -o json 2>/dev/null")

    # ---- RBAC correlation: which non-system ServiceAccounts hold a dangerous grant ----
    def rbac_subjects_with(self, verb: str, resource: str):
        """Return a list of 'ns:sa' ServiceAccount subjects bound (via any Role/ClusterRole
        binding) to a rule granting `verb` on `resource`. Excludes the kube-system / kube-public
        controllers so the finding is operator-relevant, not framework noise.

        This is the read-only heart of the K8 RBAC detectors (K8-01/14/15). Correlating roles
        with bindings is far clearer here than as nested jq."""
        if not self.have("kubectl"):
            return []
        roles = {}
        for kind in ("clusterroles", "roles"):
            data = self.kubectl_json(f"{kind} -A" if kind == "roles" else kind)
            for item in (data or {}).get("items", []):
                name = item.get("metadata", {}).get("name")
                ns = item.get("metadata", {}).get("namespace", "")
                roles[(kind[:-1], ns, name)] = item.get("rules") or []

        def rule_grants(rules) -> bool:
            for r in rules:
                verbs = r.get("verbs") or []
                res = r.get("resources") or []
                if ("*" in verbs or verb in verbs) and ("*" in res or resource in res):
                    return True
            return False

        hits = []
        for bkind, rkind in (("clusterrolebindings", "ClusterRole"), ("rolebindings", "RoleBinding")):
            data = self.kubectl_json(f"{bkind} -A" if bkind == "rolebindings" else bkind)
            for b in (data or {}).get("items", []):
                ref = b.get("roleRef", {}) or {}
                bns = b.get("metadata", {}).get("namespace", "")
                # resolve the referenced role's rules
                rules = None
                if ref.get("kind") == "ClusterRole":
                    rules = roles.get(("clusterrole", "", ref.get("name")))
                elif ref.get("kind") == "Role":
                    rules = roles.get(("role", bns, ref.get("name")))
                if not rules or not rule_grants(rules):
                    continue
                for s in (b.get("subjects") or []):
                    if s.get("kind") != "ServiceAccount":
                        continue
                    sns = s.get("namespace", bns)
                    if sns in ("kube-system", "kube-public", "kube-node-lease"):
                        continue
                    hits.append(f"{sns}:{s.get('name')}")
        return sorted(set(hits))


def rbac_detector(verb: str, resource: str, label: str):
    """Build a detect_fn that reports present iff a non-system SA holds `verb` on `resource`."""
    def _fn(ctx: Context) -> Detection:
        if not ctx.have("kubectl"):
            return Detection(None, "kubectl not available")
        subs = ctx.rbac_subjects_with(verb, resource)
        if subs:
            return Detection(True, f"{label}: " + ", ".join(subs))
        return Detection(False, f"no non-system ServiceAccount can {verb} {resource}")
    return _fn


def rbac_exploit(verb: str, resource: str, action: str, success_pat: str = None,
                 expect_marker: bool = False, setup: str = "", teardown: str = ""):
    """Build an exploit_fn that mints the token of the bound non-system SA (the armed grant) and
    performs the privileged action AS that SA — a bounded, documented technique, not a novel one.

    `action` runs under /bin/sh with $TOK (the SA's bearer token), $SANS/$SANAME (its namespace/name)
    and $MARKER in env; it should drive `kubectl --token=$TOK …`. Success is: $MARKER present in the
    output (`expect_marker`), else `success_pat` matches, else exit 0. On a host with no bound SA the
    exploit reports not-attempted (nothing armed), which is the correct 'absent' answer."""
    def _fn(ctx: Context, marker: str) -> Exploitation:
        if not ctx.have("kubectl"):
            return Exploitation(False, None, "kubectl not available")
        subs = ctx.rbac_subjects_with(verb, resource)
        if not subs:
            return Exploitation(False, None, f"no non-system SA bound to {verb} {resource} (nothing armed)")
        ns, sa = subs[0].split(":", 1)
        rc, tok = ctx.sh(f"kubectl -n {ns} create token {sa} --duration=10m 2>/dev/null")
        tok = tok.strip()
        if rc != 0 or not tok:
            return Exploitation(True, False, f"could not mint a token for {ns}:{sa}")
        env = {"MARKER": marker, "TOK": tok, "SANS": ns, "SANAME": sa}
        if setup:
            ctx.sh(setup, env=env, timeout=ctx.exploit_timeout)
        rc, out = ctx.sh(action, env=env, timeout=ctx.exploit_timeout)
        if teardown:
            ctx.sh(teardown, env=env, timeout=ctx.exploit_timeout)
        if expect_marker:
            ok = marker in out
        elif success_pat:
            ok = bool(_re.search(success_pat, out))
        else:
            ok = rc == 0
        return Exploitation(True, ok, f"as {ns}:{sa} — {out.strip()[:180]}")
    return _fn
