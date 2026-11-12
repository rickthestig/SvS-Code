#!/usr/bin/env python3
"""
Combined blue attestation: awards `block` / `remediate` only when BOTH sides independently agree.

Replaces the old attacker-report keyword matching (auto_attest.py), which could award `block` from
a phrase like "blocked" in prose and never looked at the defender's host. Evidence now comes from
three machine-checked reports:

  attacker_verify.py --label pre   (before defense: objective was `open`)      [--pre]
  attacker_verify.py --label post  (after defense:  objective is `closed`)     [--post]
  defender_verify.py               (manifest claims checked against host state) [--defender]
  defender_verify.py on pre-state  (optional, for objectives the attacker cannot probe) [--defender-pre]

Rules, per objective:
  baseline  The objective must have been vulnerable before the defense. The init/reset script
            builds an identical baseline every round, so this is assumed by default (verify a given
            host with `defender_verify.py --manifest baseline_manifest.json`: expect 0/6 verified).
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
    """Return (stage_awarded | None, [reasons]). Pure function -- unit-testable without any VM."""
    why = []
    claims = [r for r in (defender or {}).get("results", []) if r.get("objective") == obj]
    if not claims:
        return None, ["no defender manifest claim for this objective"]

    # --- baseline: was there actually something to fix? ---
    was_vuln = None
    if pre and pre["objectives"].get(obj, {}).get("status") in ("open", "closed"):
        was_vuln = pre["objectives"][obj]["status"] == "open"
        why.append(f"baseline (attacker pre): {pre['objectives'][obj]['status']}")
    elif defender_pre:
        pre_claims = [r for r in defender_pre.get("results", []) if r.get("objective") == obj]
        if pre_claims:
            was_vuln = any(not r.get("state_ok") for r in pre_claims)
            why.append(f"baseline (defender pre-state): {'vulnerable' if was_vuln else 'already fixed'}")
    if was_vuln is None and assume_baseline:
        was_vuln = True
        why.append("baseline: assumed vulnerable (rigid init script; see baseline_manifest.json)")
    if was_vuln is None:
        return None, why + ["no baseline evidence (need attacker --pre or --defender-pre); not awarding"]
    if not was_vuln:
        return None, why + ["objective was not vulnerable at baseline; nothing to credit"]

    # --- target must not simply be down ---
    if post:
        conn = post.get("connectivity", {})
        if conn and not any(v["reachable"] for v in conn.values()):
            return None, why + ["target unreachable on every service post-defense (down, not fixed)"]

    # --- attacker side ---
    post_status = (post or {}).get("objectives", {}).get(obj, {}).get("status", "not_probeable")
    attacker_confirms = post_status == "closed"
    why.append(f"attacker post probe: {post_status}")

    verified = [r for r in claims if r.get("verified")]
    unverified = [r for r in claims if not r.get("verified")]
    for r in unverified:
        why.append(f"UNVERIFIED claim '{r.get('statement')}': state_ok={r.get('state_ok')} "
                   f"legit_ok={r.get('legit_ok')} {r.get('error', '')}")
    if not verified:
        return None, why + ["no defender claim passed both its state check and legitimate-service probe"]

    # A not_probeable objective (cron/setuid/sudo without a low-priv login) cannot get attacker
    # confirmation; it is then judged on defender state + legit probe + baseline only, for remediate.
    if not attacker_confirms and post_status != "not_probeable":
        return None, why + ["attacker can still exploit it (or probe inconclusive); not awarding"]

    wants_remediate = any(r.get("claimed_stage") == "remediate" for r in claims)
    if wants_remediate and not unverified:
        return "remediate", why + (["attacker-confirmed closed"] if attacker_confirms
                                   else ["no attacker probe possible; defender-state verified only"])
    if attacker_confirms:
        return "block", why + ["attacker-confirmed closed, defender claim + service probe verified"]
    return None, why + ["block needs attacker confirmation; remediate needs all claims verified and stage=remediate"]


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
            "defender_claims": [r for r in dfn["results"] if r.get("objective") == obj],
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
