#!/usr/bin/env python3
"""
Auto-attest blue "block" credit by cross-referencing the attacker's own report against the
defender's claimed actions -- the specific case RESEARCH.md's verification matrix calls for
("independently verified prevention of the relevant attack while legitimate service works").

Why this is safe to automate (and why it only covers `block`, not `identify`/`remediate`):
  - `block` in this ledger means: the formerly-successful attacker probe now fails, AND a
    legitimate/authorized probe still succeeds. When the ATTACKER'S OWN post-defense report
    independently states the exploit no longer works, that's a genuine independent verification
    from the opposing side -- not the defender grading itself. That's exactly the kind of
    evidence a human referee would accept.
  - `identify` (1pt) requires judging whether an explanation is "correct," which is a real
    judgment call -- left to the human referee.
  - `remediate` (3pts) requires confirming the UNDERLYING FLAW is actually fixed (not just
    blocked at the edge) plus access revocation plus a functional retest -- RESEARCH.md
    explicitly warns "a failed exploit is not proof of a patch" and "avoid rewarding a defender
    for patching a flaw that was absent at baseline." Too easy to get this wrong automatically;
    left to the human referee.

This script does NOT read the defender's own claims as evidence on their own -- a defender
claiming "I blocked X" is not independent verification (see the fabricated-evidence incidents
earlier in this engagement's log). It specifically looks for the ATTACKER's own report stating
that a specific objective's exploit failed, and uses that as the independent signal.

Usage:
    python auto_attest.py <round> <objective> --attacker-report <path> --db <path-to-score.db>

It prints what it found and asks for confirmation before calling scoring.py attest, unless
--yes is passed. It writes the evidence file it used (extracted quotes from the attacker's
report) next to the database so the referee can inspect exactly what triggered the award.
"""
import argparse
import io
import pathlib
import re
import subprocess
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# This copy lives inside red-blue-lab-kit/engagement-tool/ -- scoring.py is directly one level
# up, not a sideways reach through a sibling "red-blue-lab-kit" folder like the other copy.
SCORING_PY = pathlib.Path(__file__).resolve().parent.parent / "scoring.py"

# Phrases in an ATTACKER report that, near an objective's name, indicate the attacker itself
# observed the exploit failing -- i.e. independent verification of a block, not a defender claim.
BLOCK_SIGNALS = [
    r"was rejected", r"blocked", r"no longer works", r"could not (be )?(mounted|accessed|exploited)",
    r"guest ok\s*=\s*no", r"access denied", r"authentication failed", r"could not actually be",
]


def extract_evidence(report_text: str, objective: str, window: int = 400) -> list[str]:
    """Find passages near the objective name that also contain a block signal phrase.
    Overlapping windows are merged into one passage so near-duplicate hits don't repeat."""
    ranges = []
    for m in re.finditer(re.escape(objective), report_text, re.IGNORECASE):
        start = max(0, m.start() - window)
        end = min(len(report_text), m.end() + window)
        snippet = report_text[start:end]
        if any(re.search(sig, snippet, re.IGNORECASE) for sig in BLOCK_SIGNALS):
            ranges.append((start, end))
    if not ranges:
        return []
    ranges.sort()
    merged = [ranges[0]]
    for start, end in ranges[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end:  # overlap or touching -> merge
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return [report_text[s:e].strip() for s, e in merged]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("round")
    p.add_argument("objective", help="ssh | smb | web | cron | setuid | sudo")
    p.add_argument("--attacker-report", required=True, type=pathlib.Path)
    p.add_argument("--db", default=str(SCORING_PY.parent / "private" / "score.db"))
    p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    args = p.parse_args()

    if not args.attacker_report.is_file():
        sys.exit(f"Attacker report not found: {args.attacker_report}")
    text = args.attacker_report.read_text(encoding="utf-8", errors="replace")

    hits = extract_evidence(text, args.objective)
    if not hits:
        print(f"No independent block evidence found for '{args.objective}' in the attacker's "
              f"own report. Not attesting -- this requires either different evidence or a "
              f"human referee's manual judgment.")
        return

    print(f"Found {len(hits)} passage(s) in the attacker's report suggesting '{args.objective}' "
          f"was independently observed as blocked:\n")
    for i, h in enumerate(hits, 1):
        print(f"--- passage {i} ---\n{h}\n")

    if not args.yes:
        ans = input("Attest blue 'block' (2 pts) for this objective based on the above? [y/N] ")
        if ans.strip().lower() != "y":
            print("Not attesting.")
            return

    evidence_path = args.attacker_report.parent / f"auto-attest-{args.round}-{args.objective}-block.txt"
    evidence_path.write_text(
        f"Auto-attest evidence for round={args.round} objective={args.objective} stage=block\n"
        f"Source: attacker's own report at {args.attacker_report}\n"
        f"Independent-verification passages:\n\n" + "\n\n".join(hits),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(SCORING_PY), "--db", args.db, "attest",
         args.round, "blue", args.objective, "block", str(evidence_path.resolve())],
        capture_output=True, text=True, cwd=SCORING_PY.parent,
    )
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)


if __name__ == "__main__":
    main()
