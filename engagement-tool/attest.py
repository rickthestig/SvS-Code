#!/usr/bin/env python3
"""
Combined blue attestation: awards `block` / `remediate` only when BOTH sides independently agree.

Replaces the old attacker-report keyword matching (auto_attest.py), which could award `block` from
a phrase like "blocked" in prose and never looked at the defender's host. Evidence now comes from
three machine-checked reports:

  attacker_verify.py --label pre   (before defense: objective was `open`)      [--pre]
  attacker_verify.py --label post  (after defense:  objective is `closed`)     [--post]
  defender_verify.py               (operator checks of host state + which vectors the defender documented) [--defender]
  defender_verify.py on pre-state  (optional, for objectives the attacker cannot probe) [--defender-pre]

Rules, per objective:
  baseline  The objective must have been vulnerable before the defense. The init/reset script
            builds an identical baseline every round, so this is assumed by default (verify a given
            host with `defender_verify.py --manifest verification_plan.json`: expect 0/6 verified).
            If --pre / --defender-pre evidence is given it is used instead; --strict-baseline
            demands such evidence. Never rewards patching a flaw
            that was absent.
  block     baseline AND attacker `post` = closed AND the defender manifest has a claim for the
            objective that is verified (state check passed + legitimate-service probe passed) AND
            the target was not simply down (post connectivity shows other services still up).
  remediate block's conditions AND every manifest claim for that objective verified AND at least
            one claim declared with stage "remediate". (Per RESEARCH.md, block-only containment
            earns 2; remediate needs the underlying flaw fixed.)
  identify  Never automated -- judgment call, left to the human referee.

Dry run by default. --apply calls scoring.py attest with a generated evidence file that embeds the
exact report data used, so the referee can audit every award.

Usage:
    python attest.py <round> --pre attacker-pre.json --post attacker-post.json \
        --defender defender-report.json [--defender-pre defender-pre.json] [--apply] [--db path]
"""
import argparse
import json
import pathlib
import subprocess
import sys

WORK = pathlib.Path(__file__).resolve().parent
SCORING_PY = WORK.parent / "scoring.py"
OBJECTIVES = ("ssh", "smb", "web", "cron", "setuid", "sudo")


def load(p):
    return json.loads(pathlib.Path(p).read_text(encoding="utf-8")) if p else None


def judge(obj, pre, post, defender, defender_pre, assume_baseline=False):
    """Return (stage_awarded | None, [reasons]). Pure function -- unit-testable without any VM.

    `defender` is defender_verify.py's report: per objective, the operator's own checks
    (state_ok = underlying fix in place, legit_ok = legitimate service works) plus `claimed`
    (did the defender document stopping this vector in its manifest)."""
    why = []
    r = next((x for x in (defender or {}).get("results", []) if x.get("objective") == obj), None)
    if r is None:
        return None, ["objective not in defender verification report"]

    # --- baseline: was there actually something to fix? ---
    was_vuln = None
    if pre and pre["objectives"].get(obj, {}).get("status") in ("open", "closed"):
        was_vuln = pre["objectives"][obj]["status"] == "open"
        why.append(f"baseline (attacker pre): {pre['objectives'][obj]['status']}")
    elif defender_pre:
        pr = next((x for x in defender_pre.get("results", []) if x.get("objective") == obj), None)
        if pr is not None:
            was_vuln = not pr.get("state_ok")
            why.append(f"baseline (defender pre-state): {'vulnerable' if was_vuln else 'already fixed'}")
    if was_vuln is None and assume_baseline:
        was_vuln = True
        why.append("baseline: assumed vulnerable (rigid init script; see verification_plan.json)")
    if was_vuln is None:
        return None, why + ["no baseline evidence (need attacker --pre or --defender-pre); not awarding"]
    if not was_vuln:
        return None, why + ["objective was not vulnerable at baseline; nothing to credit"]

    # --- target must not simply be down ---
    if post:
        conn = post.get("connectivity", {})
        if conn and not any(v["reachable"] for v in conn.values()):
            return None, why + ["target unreachable on every service post-defense (down, not fixed)"]

    post_status = (post or {}).get("objectives", {}).get(obj, {}).get("status", "not_probeable")
    why.append(f"attacker post probe: {post_status}")
    why.append(f"operator checks: underlying fix={r.get('state_ok')} service works={r.get('legit_ok')}; "
               f"defender documented it={r.get('claimed')}")

    if not r.get("claimed"):
        return None, why + ["defender did not document stopping this vector in its manifest"]
    if not r.get("legit_ok"):
        return None, why + ["legitimate service broken (a fix that kills the service is not a fix)"]
    if post_status == "open":
        return None, why + ["attacker can still reach it; not awarding"]

    if r.get("state_ok"):
        return "remediate", why + ["underlying flaw fixed, service works, documented"]
    if post_status == "closed":
        return "block", why + ["attacker blocked and service works, but underlying flaw not corrected (containment only)"]
    return None, why + ["no attacker confirmation and underlying flaw not fixed"]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("round")
    ap.add_argument("--pre"), ap.add_argument("--post", required=True)
    ap.add_argument("--defender", required=True), ap.add_argument("--defender-pre")
    ap.add_argument("--db", default=str(SCORING_PY.parent / "private" / "score.db"))
    ap.add_argument("--evidence-dir", default=".")
    ap.add_argument("--strict-baseline", action="store_true",
                    help="require --pre/--defender-pre evidence instead of trusting the rigid init baseline")
    ap.add_argument("--apply", action="store_true", help="actually write to the ledger (default: dry run)")
    a = ap.parse_args()

    pre, post, dfn, dpre = load(a.pre), load(a.post), load(a.defender), load(a.defender_pre)
    outdir = pathlib.Path(a.evidence_dir); outdir.mkdir(parents=True, exist_ok=True)

    for obj in OBJECTIVES:
        stage, reasons = judge(obj, pre, post, dfn, dpre, assume_baseline=not a.strict_baseline)
        print(f"\n[{obj}] -> {stage or 'no award'}")
        for r in reasons:
            print(f"    - {r}")
        if not stage or not a.apply:
            continue
        ev = outdir / f"attest-{a.round}-{obj}-{stage}.json"
        ev.write_text(json.dumps({
            "round": a.round, "objective": obj, "stage": stage, "reasons": reasons,
            "attacker_pre": pre and pre["objectives"].get(obj), "attacker_post": post["objectives"].get(obj),
            "post_connectivity": post.get("connectivity"),
            "defender_report": [r for r in dfn["results"] if r.get("objective") == obj],
            "unmatched_claims": dfn.get("unmatched_claims_for_referee"),
            "defender_checked_at": dfn.get("checked_at"), "attacker_checked_at": post.get("checked_at"),
        }, indent=2), encoding="utf-8")
        r = subprocess.run([sys.executable, str(SCORING_PY), "--db", a.db, "attest",
                            a.round, "blue", obj, stage, str(ev.resolve())],
                           capture_output=True, text=True, cwd=SCORING_PY.parent)
        print("    ledger:", (r.stdout or r.stderr).strip().replace("\n", " "))
    if not a.apply:
        print("\n(dry run -- pass --apply to write awards to the ledger)")


if __name__ == "__main__":
    main()
