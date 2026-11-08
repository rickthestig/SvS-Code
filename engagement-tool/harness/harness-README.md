# Attacker harness — `~/harness` on Kali-3

This is your persistent workspace for this engagement. It's installed once and reused across runs — its
structure and any tooling in it survive between engagements, but its **contents are wiped before every
new run** (see `reset.sh`). Nothing you leave here carries over to the next engagement; don't rely on
anything from a previous run still being here.

You're running natively on Kali-3 with your own Bash tool — there's no SSH-relay harness restricting you,
this is just a place to keep things organized so the operator can find your output afterward.

## Layout

- `scope/` — the current engagement's scope document(s) go here. Read everything in this directory in
  full before acting; it's your authorization and rules of engagement.
- `logs/` — your running log and final report go here (see the scope doc for exactly what's required).
  Use this directory specifically, not your home directory root or somewhere ad hoc — it's what gets
  pulled off after the engagement.
- `loot/` — captured flags, credentials, interesting files you pull from targets, anything you'd call
  "evidence." One subfolder per target is reasonable (`loot/<target>/`) but not required.
- `scans/` — raw tool output (nmap, nuclei, whatever you run) — keep it here instead of scattering output
  files across your home directory.

## Reset

`reset.sh` (in this directory) empties `loot/`, `logs/`, and `scans/`, clears the scope directory (a fresh
scope doc gets copied in before each run), and clears your own prior Claude Code session history tied to
this directory — so each run starts with a genuinely blank slate, not just an empty-looking one. It does
**not** touch the lab network, the targets, or anything outside this directory. Run it yourself only if
asked to; normally the operator runs it between engagements.
