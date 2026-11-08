# Red and blue team lab runner

Scores and archives a red-vs-blue round in the GNS3 lab. This file describes how the exercise
**actually runs today**; see the note at the bottom about files in this repo that reflect an
earlier, superseded design.

## Running an exercise

The actual orchestration tool is `engagement-tool/`, a self-contained CLI — everything it needs
(GNS3/Kali SSH pivot, the admin key, vendored SSH libraries, scope docs) lives alongside it. Run
from inside that folder, with GNS3 running and the GNS3 VM reachable:

```powershell
cd engagement-tool
python engagement.py check            # verify GNS3 VM/Kali/targets/keys are all reachable first
python engagement.py start            # full reset + kickoff: both agents launched together
python engagement.py status --watch   # live status until both finish
python engagement.py collect          # pull results, submit captured flags, auto-attest, archive
python engagement.py stop             # stop both agents mid-run if something needs aborting
```

Full detail — what each step actually does, where scope docs and API keys live, why targets get
power-cycled the way they do, the fairness/anti-leak mechanisms baked into the harness — is in
[`engagement-tool/ENGAGEMENT_TOOL_README.md`](engagement-tool/ENGAGEMENT_TOOL_README.md).

The attacker runs Claude Code natively on Kali against the scope doc in `engagement-tool/scope/`;
the defender is `engagement-tool/defender_agent.py`, a Mistral-driven agent with a single
`execute(target, command)` tool over SSH. Both read their API key from a plain-text file
(`engagement-tool/defender.txt`, `engagement-tool/attacker.txt`) — see the tool's own README for
which is required vs. optional right now.

## What's still used directly from this repo

- `scoring.py` — the one real scoring ledger (`private/score.db`). `engagement.py collect` calls
  this to submit captured flags and check for automatable blue "block" credit; you can also run it
  by hand for manual referee attestation (`identify`/`remediate`, which aren't automated on
  purpose — see `RESEARCH.md`'s verification matrix for why).
- `install_flags.py` — plants the four `FLAG{...}` fixtures on Ubuntu-Weak before a round.
  `engagement.py start` calls this automatically; see it here if you need to run it by hand.
- `RESEARCH.md` — the scoring design and point-table rationale. Still accurate; read this before
  changing anything about how points are awarded.

## Files reflecting an earlier, superseded design

`bridge.py`, `client.py`, `trials.py`, `human.py`, `ssh_config.example`, `red.example.json`,
`blue.example.json`, `reset.example.json`, and the `reset-lab.py` in *this* directory (not
`engagement-tool/reset-lab.py`, which is a different, actually-used script with hardcoded node
IDs rather than a `reset.local.json`) all belong to an earlier design: two independently
authenticated HTTP-to-SSH bridges that a model's own tool-calling adapter would connect to,
configured via `ssh_config`/`red.json`/`blue.json`. That design was superseded by having the
attacker run natively on Kali (via Opencode) and the defender as a direct Python/SSH agent
(`defender_agent.py`) — no bridge API in between. These files are kept for reference, not part of
the current workflow. `OPERATOR_GUIDE.md` and `EXPERIMENTS.md` describe that older design in
detail and haven't been updated to match the current one.
