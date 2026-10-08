"""`datsu validate` — self-test the detectors and exploiters on a disposable lab.

For each scenario it answers two questions and records the evidence + reproducible steps:

  Q1  can datsu DETECT the precondition?   -> arm the condition, run the detector, tear it down
  Q2  can datsu EXPLOIT the vulnerability?  -> run the (self-arming, marker-stamped) exploiter

Version/CVE and host-state scenarios that cannot be armed on demand are reported honestly as
"detector run against the node's ambient state" and "exploit N/A by design". The output is a
report (preconditions + Q1/Q2 results + reproduce steps) suitable for an engagement write-up.

DESTRUCTIVE — arms real escape conditions and runs exploits. Disposable, isolated lab only.

Author: d3vn0mi (RavenSec)
"""
from __future__ import annotations

import re

from .context import Context
from .model import Confidence, Repro
from .scenarios import SCENARIOS


def _first_line(s: str) -> str:
    return (s or "").strip().splitlines()[0][:160] if (s or "").strip() else ""


def validate_scenario(ctx: Context, s, marker: str, settle: int = 4) -> dict:
    marker_full = f"ESCAPE_{s.id}_{marker}"
    rec = {"id": s.id, "class": s.kind.value, "severity": s.severity, "repro": s.repro.value,
           "confidence": s.confidence.value, "vector": s.vector, "triage_ref": s.triage_ref,
           "preconditions": s.preconditions or s.note or s.vector,
           "cves": re.findall(r"CVE-\d{4}-\d+", s.note or ""),
           "arm_steps": s.arm_sh, "exploit_cmd": f"datsu exploit --id {s.id} --marker <token>"}

    # ---- Q1: detection ----
    if s.arm_sh:
        ctx.sh(s.arm_sh, timeout=ctx.exploit_timeout)
        ctx.sh(f"sleep {settle}")
        d = s.detect(ctx)
        rec["q1"] = {"armed": True,
                     "result": "DETECTED" if d.present else ("INCONCLUSIVE" if d.present is None else "MISSED"),
                     "evidence": _first_line(d.evidence)}
        if s.cleanup_sh:
            ctx.sh(s.cleanup_sh, timeout=ctx.exploit_timeout)
    else:
        d = s.detect(ctx)
        rec["q1"] = {"armed": False,
                     "result": ("AMBIENT-PRESENT" if d.present else
                                ("INCONCLUSIVE" if d.present is None else "AMBIENT-ABSENT")),
                     "evidence": _first_line(d.evidence)}

    # ---- Q2: exploitation (self-arming, marker-stamped) ----
    ex = s.exploit(ctx, marker_full)
    if s.repro is Repro.VERSION or s.repro is Repro.NA or s.confidence is Confidence.PRECONDITION:
        rec["q2"] = {"result": "N/A-BY-DESIGN", "evidence": _first_line(ex.evidence)}
    else:
        rec["q2"] = {"result": ("EXPLOITED" if ex.success else
                                ("INCONCLUSIVE" if ex.success is None else "FAILED")),
                     "evidence": _first_line(ex.evidence)}
    return rec


def run(ctx: Context, scenarios, marker: str) -> list:
    return [validate_scenario(ctx, s, marker) for s in scenarios]


# ---------------------------------------------------------------------------- report

_Q1_OK = {"DETECTED", "AMBIENT-PRESENT"}
_Q2_OK = {"EXPLOITED", "N/A-BY-DESIGN"}


def summarize(records: list) -> dict:
    return {
        "total": len(records),
        "detected": sum(r["q1"]["result"] == "DETECTED" for r in records),
        "missed": sum(r["q1"]["result"] == "MISSED" for r in records),
        "ambient_present": sum(r["q1"]["result"] == "AMBIENT-PRESENT" for r in records),
        "exploited": sum(r["q2"]["result"] == "EXPLOITED" for r in records),
        "exploit_failed": sum(r["q2"]["result"] == "FAILED" for r in records),
        "exploit_na": sum(r["q2"]["result"] == "N/A-BY-DESIGN" for r in records),
    }


def report_md(records: list, marker: str, when: str = "") -> str:
    s = summarize(records)
    g1 = {"DETECTED": "✅ detected", "MISSED": "❌ MISSED", "INCONCLUSIVE": "⚠️ inconclusive",
          "AMBIENT-PRESENT": "✅ present (ambient)", "AMBIENT-ABSENT": "— absent (arm to test)"}
    g2 = {"EXPLOITED": "✅ exploited", "FAILED": "❌ FAILED", "INCONCLUSIVE": "⚠️ inconclusive",
          "N/A-BY-DESIGN": "— N/A by design"}
    out = []
    out.append("# datsu validation report")
    out.append("")
    out.append(f"**Run marker:** `{marker}`" + (f"  ·  **When:** {when}" if when else ""))
    out.append("")
    out.append("Two questions per scenario: **Q1** — can datsu detect the precondition? "
               "**Q2** — can datsu exploit it? Each armed on a disposable lab, torn down after.")
    out.append("")
    out.append("## Summary")
    out.append("")
    out.append(f"- Scenarios validated: **{s['total']}**")
    out.append(f"- Q1 detection: **{s['detected']} detected** (armed), {s['ambient_present']} present ambient, "
               f"**{s['missed']} missed**")
    out.append(f"- Q2 exploitation: **{s['exploited']} exploited**, {s['exploit_failed']} failed, "
               f"{s['exploit_na']} N/A-by-design (version / precondition / n-a)")
    out.append("")
    out.append("| Scenario | Vector | Sev | Q1 detect | Q2 exploit |")
    out.append("|----|----|----|----|----|")
    for r in records:
        out.append(f"| {r['id']} | {r['vector'][:52].replace('|','\\|')} | {r['severity']} | "
                   f"{g1.get(r['q1']['result'], r['q1']['result'])} | {g2.get(r['q2']['result'], r['q2']['result'])} |")
    out.append("")
    out.append("## Per-scenario detail")
    out.append("")
    for r in records:
        cves = (" · " + ", ".join(r["cves"])) if r["cves"] else ""
        out.append(f"### {r['id']} — {r['vector']}")
        out.append("")
        out.append(f"*{r['class']} · {r['severity']} · {r['repro']}/{r['confidence']}"
                   + (f" · triage {r['triage_ref']}" if r['triage_ref'] else "") + cves + "*")
        out.append("")
        out.append(f"- **Preconditions:** {r['preconditions']}")
        out.append(f"- **Q1 — detect precondition:** {g1.get(r['q1']['result'], r['q1']['result'])}"
                   + (f" — `{r['q1']['evidence']}`" if r['q1']['evidence'] else ""))
        out.append(f"- **Q2 — exploit:** {g2.get(r['q2']['result'], r['q2']['result'])}"
                   + (f" — `{r['q2']['evidence']}`" if r['q2']['evidence'] else ""))
        out.append("- **Reproduce:**")
        if r["arm_steps"]:
            out.append("  - *Arm the precondition:*")
            out.append("    ```sh")
            for ln in r["arm_steps"].splitlines():
                out.append("    " + ln)
            out.append("    ```")
        else:
            out.append("  - *Arm:* not auto-armable in-harness (version/host-state) — see preconditions above.")
        out.append(f"  - *Detect:* `datsu detect --only {r['id']}`")
        out.append(f"  - *Exploit:* `{r['exploit_cmd']}`")
        out.append("")
    out.append("---")
    out.append("")
    out.append("Generated by `datsu validate`. Author: d3vn0mi (RavenSec).")
    return "\n".join(out)
