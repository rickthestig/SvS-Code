# `engagement.py` — running a red-vs-blue round without doing it by hand

This replaces the ~20 manual steps a full run used to take (reset targets, reinstall flags, sweep
Kali for stale recon data, upload scope docs, verify they landed, launch both agents, poll status,
pull results, submit flags, run attestation, archive) with four commands. This is a copy of the
tool living inside the git-tracked `red-blue-lab-kit/` repo, at `red-blue-lab-kit/engagement-tool/`
(a second, independent copy lives at `Research/engagement-tool/` — both are fully self-contained
and correctly work out of their own location; edits don't propagate between them). Everything this
copy needs to run (`lab.py`, `reset-lab.py`, `target_task.py`, the `pydeps/` vendored SSH
libraries, the admin SSH key and pinned known_hosts, the scope docs) lives alongside
`engagement.py` itself. Run everything from here, with GNS3 running and the GNS3 VM reachable.
`python engagement.py check` verifies all of that before you commit to a multi-minute `start`.

### Where things live, and why

- **Scope docs** (`scope/AGENT_PENTEST_SCOPE.md`, `scope/DEFENDER_SCOPE.md`) are canonical *here*
  now — edit these, not any older copy elsewhere. `start` uploads the attacker-facing one to Kali
  and reads the defender-facing one straight off disk at launch.
- **Run output** (the continuous `ENGAGEMENT_LOG.md`, defender transcripts, archived
  `run-results-*/` folders) stays in `../../Test Run/`, reached by a relative path from here — not
  duplicated into this folder, so the project's one running history doesn't fork the day this tool
  was built.
- **The scoring ledger** (`private/score.db`, flag bundles) is the one real copy, directly one
  level up at `../scoring.py` / `../private/` — this copy of the tool is *inside* `red-blue-lab-kit/`
  itself now, so there's no sideways reach and no separate reference copy needed here.

## API keys

Both sides read their key from a plain-text file in this folder containing nothing but the key:

- `defender.txt` — Mistral API key. Required; `defender_agent.py` exits immediately if it's
  missing or empty.
- `attacker.txt` — Anthropic API key. Optional for now: if present and non-empty, `start` exports
  it as `ANTHROPIC_API_KEY` for the attacker's `claude` launch; if absent, the attacker falls back
  to whatever `claude` auth session is already active on Kali (fine for today's test runs, but the
  full run needs this file so the attacker authenticates by key rather than a shared login state).

Both files are gitignored — see `.gitignore` in this folder.

## Quick start

```powershell
# Full reset + kickoff — resets both targets to clean baseline, creates a fresh scoring round,
# installs flags, sweeps Kali (harness contents, shell history, known_hosts), uploads scope docs,
# and launches both agents together. Takes a few minutes before the agents even start, since
# resetting the 8GB+ target disks isn't instant.
python engagement.py start

# Watch it live (refreshes until both agents finish; Ctrl+C just stops watching, not the agents)
python engagement.py status --watch

# Once both are done: pull logs/loot/scans off Kali, copy the defender transcript, parse captured
# flags out of loot/flags.md and submit them to the scoring ledger, check for automatable blue
# "block" credit, and archive everything into Test Run/run-results-<date>-<round>/
python engagement.py collect
```

If something needs aborting mid-run:

```powershell
python engagement.py stop    # stops both agents; targets/harness are left as-is for inspection
```

## What `start` actually does, in order

1. Disk-reset Ubuntu-Weak and Ubuntu-IoT to the clean baseline (unless `--skip-target-reset`).
2. Create a fresh scoring round (or reuse one with `--reuse-round`) and install its flags on
   Ubuntu-Weak, then shut it down cleanly.
3. Take both targets fully down — not just reset, actually powered off — before anything else
   happens. A partial reset or flag-install session shows up in the targets' own logs, and if
   that's still sitting there when the defender starts its own log analysis, it reads as recent
   activity right at the point it starts looking, which has caused real false attribution before.
4. Reset the attacker harness on Kali (`~/harness`'s loot/logs/scans/scope, this harness's prior
   Claude Code session history, stray files dropped directly in `$HOME`, shell history, and SSH
   `known_hosts`) — closing off every way a fresh run could get a head start from a previous one.
5. Upload the scope docs with this round's name substituted in.
6. Power both targets back on and re-verify blue (defender) SSH access.
7. **Verify the scope doc actually landed non-empty on the harness before launching anything.**
   This exact mistake (re-running the harness reset after uploading the scope doc, wiping it,
   and launching anyway) caused a wasted defender run earlier in this engagement — the attacker
   caught it and halted itself per its own instructions, but the defender had already finished
   against a quiet target by the time anyone noticed. This check exists specifically so that
   can't happen silently again.
8. Launch Claude Code on Kali in the background, retrying automatically on the (observed,
   intermittent, so far always transient) auto-mode classifier block.
9. Launch the Mistral defender as a tracked child process.
10. Save round name / session ID / defender PID to `.engagement_state.json` so `status`,
    `collect`, and `stop` don't need any of that passed back in.

## Fairness checks already built into the harness (not this script, but why `start` trusts it)

- The defender's `ssh_execute()` redacts `FLAG{...}` token content and the `thesis-flag.txt`
  filename out of everything a command returns, so it can't shortcut straight to the scored
  objective paths via `grep -r FLAG{ /` instead of finding them through real analysis.
- Its evidence-fabrication check (`verify_claimed_files()`) catches claims made as bare filenames
  in a table, not just "saved to /path" phrasing.
- `reset.sh` sweeps `$HOME` (not just `~/harness`) and clears shell history, closing the two ways
  this engagement has actually leaked prior-run target IPs into a "fresh" run.

## Notes

- `start --skip-target-reset` still power-cycles the targets cleanly (so you don't inherit a
  previous run's SSH/log noise) — it just skips the disk-reset and flag-reinstall, for a quick
  relaunch when you know the targets are already in a usable state.
- `--reuse-round` skips creating a new scoring round if the previous one never had anything
  submitted to it — avoids burning round numbers on aborted attempts.
- `collect` is safe to re-run; flag submission is idempotent (the ledger rejects duplicates) and
  `auto_attest.py` only ever auto-awards `block` credit with its own conservative, narrow signal
  matching — `identify` and `remediate` are left to a human referee on purpose, see RESEARCH.md.
