"""`datsu` command-line interface.

    datsu list                         # the catalogue
    datsu detect [--json] [--class k8s] [--only DK-02 K8-09] [--fail-on-present]
    datsu exploit --id K8-09 --marker RS1   # one, gated
    datsu exploit --all   --marker RS1       # every detected, exploitable condition

Detection is always read-only. Exploitation changes state, so it is gated behind an explicit
`--marker` (the run sentinel) and prints the rules-of-engagement banner; without a marker the
tool refuses. Run this only against systems you are authorized to test.

Author: d3vn0mi (RavenSec)
"""
from __future__ import annotations

import argparse
import json
import sys

from .context import Context
from .model import Repro
from .scenarios import SCENARIOS, get

BANNER = (
    "datsu — container & Kubernetes escape validation\n"
    "AUTHORIZED USE ONLY. Detection is read-only; exploitation changes node state and is\n"
    "intended for an operator-owned, isolated, disposable lab (the RavenSec escape engagement).\n"
)

_GLYPH = {"PRESENT": "[+]", "ABSENT": "[-]", "UNKNOWN": "[?]",
          "SUCCESS": "[+]", "FAILED": "[x]", "SKIPPED": "[.]", "INCONCLUSIVE": "[?]"}


def _select(args):
    scns = SCENARIOS
    if getattr(args, "cls", None):
        scns = [s for s in scns if s.kind.value == args.cls]
    if getattr(args, "only", None):
        want = {x.upper() for x in args.only}
        scns = [s for s in scns if s.id in want]
    return scns


def cmd_list(args):
    scns = _select(args)
    if args.json:
        print(json.dumps([{"id": s.id, "class": s.kind.value, "repro": s.repro.value,
                           "vector": s.vector, "severity": s.severity, "triage_ref": s.triage_ref,
                           "confidence": s.confidence.value, "note": s.note} for s in scns], indent=2))
        return 0
    print(f"{len(scns)} scenarios\n")
    for s in scns:
        ref = f" triage={s.triage_ref}" if s.triage_ref else ""
        print(f"  {s.id:<6} {s.kind.value:<6} {s.severity:<8} {s.vector}")
        print(f"         {s.repro.value}/{s.confidence.value}{ref}")
    return 0


def cmd_detect(args):
    ctx = Context(dry_run=args.dry_run, verbose=args.verbose)
    scns = _select(args)
    results = []
    for s in scns:
        d = s.detect(ctx)
        results.append((s, d))
    if args.json:
        print(json.dumps([{"id": s.id, "class": s.kind.value, "vector": s.vector,
                           "severity": s.severity, "repro": s.repro.value, "triage_ref": s.triage_ref,
                           "state": d.state, "present": d.present, "evidence": d.evidence}
                          for s, d in results], indent=2))
    else:
        print(BANNER)
        width = max((len(s.vector) for s, _ in results), default=10)
        for s, d in results:
            print(f"  {_GLYPH[d.state]} {s.id:<6} {d.state:<8} {s.vector:<{width}}")
            if d.evidence and d.present is not False:
                print(f"            └ {d.evidence.splitlines()[0][:100]}")
        present = [s.id for s, d in results if d.present]
        unknown = [s.id for s, d in results if d.present is None]
        print(f"\n  {len(present)} present, {len(unknown)} inconclusive, "
              f"{len(results) - len(present) - len(unknown)} absent")
        if present:
            print("  present: " + ", ".join(present))
    if args.fail_on_present and any(d.present for _, d in results):
        return 1
    return 0


def cmd_exploit(args):
    if not args.marker:
        sys.stderr.write(BANNER + "\nRefusing to exploit without --marker <token> (the run sentinel).\n"
                         "Pick any short token for this authorized run, e.g. --marker RS_$(date +%s).\n")
        return 2
    ctx = Context(dry_run=args.dry_run, verbose=args.verbose)
    print(BANNER)
    print(f"  run marker: {args.marker}\n")

    if args.id:
        s = get(args.id)
        if not s:
            sys.stderr.write(f"unknown scenario: {args.id}\n")
            return 2
        targets = [s]
    else:  # --all: only conditions actually present and exploitable
        targets = []
        for s in SCENARIOS:
            if s.repro is not Repro.CONFIG:
                continue
            if s.detect(ctx).present:
                targets.append(s)
        if not targets:
            print("  no present, exploitable conditions detected — nothing to do.")
            return 0

    results = []
    for s in targets:
        marker = f"ESCAPE_{s.id}_{args.marker}"
        ex = s.exploit(ctx, marker)
        results.append((s, ex))
        line = ex.evidence.splitlines()[0][:120] if ex.evidence else ""
        print(f"  {_GLYPH[ex.state]} {s.id:<6} {ex.state:<12} {s.vector}")
        if line:
            print(f"            └ {line}")

    if args.json:
        print("\n" + json.dumps([{"id": s.id, "vector": s.vector, "marker": f"ESCAPE_{s.id}_{args.marker}",
                                  "state": ex.state, "attempted": ex.attempted, "success": ex.success,
                                  "evidence": ex.evidence} for s, ex in results], indent=2))
    succeeded = [s.id for s, ex in results if ex.success]
    failed = [s.id for s, ex in results if ex.attempted and ex.success is False]
    print(f"\n  {len(succeeded)} proven, {len(failed)} failed, "
          f"{len(results) - len(succeeded) - len(failed)} skipped/inconclusive")
    if succeeded:
        print("  proven: " + ", ".join(succeeded))
    return 1 if failed else 0


def cmd_validate(args):
    if not args.marker:
        sys.stderr.write(BANNER + "\nRefusing to validate without --marker <token>.\n"
                         "`validate` ARMS real escape conditions and runs exploits — disposable, isolated lab ONLY.\n")
        return 2
    from . import validate as _v
    import datetime
    ctx = Context(dry_run=args.dry_run, verbose=args.verbose)
    if getattr(args, "settle", None):
        pass
    scns = _select(args)
    print(BANNER)
    print("  ⚠  ARMING real escape conditions + running exploits. Disposable isolated lab ONLY.")
    print(f"  run marker: {args.marker}  ·  scenarios: {len(scns)}\n")
    if getattr(args, "arm_all", False):
        print("  mode: arm-all (every precondition satisfied simultaneously)\n")
        records = _v.validate_all(ctx, scns, args.marker, settle=args.settle)
        for rec in records:
            print(f"  {rec['id']:<6} Q1:{rec['q1']['result']:<15} Q2:{rec['q2']['result']:<14} {rec['vector'][:48]}")
    else:
        records = []
        for s in scns:
            rec = _v.validate_scenario(ctx, s, args.marker, settle=args.settle)
            records.append(rec)
            q1 = rec["q1"]["result"]; q2 = rec["q2"]["result"]
            print(f"  {s.id:<6} Q1:{q1:<15} Q2:{q2:<14} {s.vector[:48]}")
    when = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    if args.json:
        print("\n" + json.dumps({"marker": args.marker, "summary": _v.summarize(records),
                                 "records": records}, indent=2))
    md = _v.report_md(records, args.marker, when)
    if args.report:
        try:
            with open(args.report, "w") as f:
                f.write(md)
            print(f"\n  report written: {args.report}")
        except OSError as e:
            sys.stderr.write(f"could not write report: {e}\n")
            print("\n" + md)
    else:
        print("\n" + md)
    su = _v.summarize(records)
    print(f"\n  Q1 {su['detected']} detected / {su['missed']} missed · "
          f"Q2 {su['exploited']} exploited / {su['exploit_failed']} failed / {su['exploit_na']} n-a")
    return 1 if (su["missed"] or su["exploit_failed"]) else 0


def build_parser():
    p = argparse.ArgumentParser(prog="datsu",
        description="Detect (read-only) and, when authorized, exploit container & Kubernetes escape conditions.")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--json", action="store_true", help="machine-readable JSON output")
        sp.add_argument("--class", dest="cls", choices=["docker", "k8s"], help="limit to one class")
        sp.add_argument("--only", nargs="+", metavar="ID", help="limit to specific scenario ids")

    pl = sub.add_parser("list", help="list the scenario catalogue")
    common(pl)
    pl.set_defaults(func=cmd_list)

    pd = sub.add_parser("detect", help="read-only: which escape conditions are present")
    common(pd)
    pd.add_argument("--dry-run", action="store_true", help="print commands, do not execute")
    pd.add_argument("--verbose", action="store_true", help="echo each command")
    pd.add_argument("--fail-on-present", action="store_true", help="exit 1 if any condition is present (CI gate)")
    pd.set_defaults(func=cmd_detect)

    px = sub.add_parser("exploit", help="gated: demonstrate the escape for a condition (needs --marker)")
    g = px.add_mutually_exclusive_group(required=True)
    g.add_argument("--id", metavar="ID", help="exploit one scenario by id")
    g.add_argument("--all", action="store_true", help="exploit every detected, exploitable condition")
    px.add_argument("--marker", metavar="TOKEN", help="run sentinel stamped into every proof artifact")
    px.add_argument("--json", action="store_true", help="machine-readable JSON output")
    px.add_argument("--dry-run", action="store_true", help="print commands, do not execute")
    px.add_argument("--verbose", action="store_true", help="echo each command")
    px.set_defaults(func=cmd_exploit)

    pv = sub.add_parser("validate", help="gated: arm each condition on a disposable lab, run detect + exploit, write a report")
    common(pv)
    pv.add_argument("--marker", metavar="TOKEN", help="run sentinel (required; validate arms + exploits)")
    pv.add_argument("--report", metavar="PATH", help="write the markdown report to PATH (else stdout)")
    pv.add_argument("--settle", type=int, default=4, help="seconds to wait after arming before detecting (default 4)")
    pv.add_argument("--arm-all", action="store_true", help="arm every precondition at once (one detect pass + teardown), instead of per-scenario arm/cleanup")
    pv.add_argument("--dry-run", action="store_true", help="print commands, do not execute")
    pv.add_argument("--verbose", action="store_true", help="echo each command")
    pv.set_defaults(func=cmd_validate)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        return 130


if __name__ == "__main__":
    sys.exit(main())
