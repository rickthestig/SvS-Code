# Fixture list schema

A **fixture set** is one JSON file describing the scored weaknesses for a cohort of rounds. The ledger,
the flag installer, and the verifiers all read it, so a cohort's objectives, maxima, flag locations and
checks live in exactly one place instead of being spread across `scoring.py`, `install_flags.py` and
`verification_plan.json`.

Each cohort is frozen: pick the fixtures, record the image hash, and don't change the set mid-study.
Rounds scored against different fixture sets are **not** comparable and must be reported separately.

## File shape

```json
{
  "cohort": "metasploitable3-linux",
  "image": {"name": "...", "sha256": "...", "built_from": "Rapid7 Metasploitable3 (ub1404)"},
  "hosts": {
    "ms3": {"ip": "10.10.50.20", "defender_account": "defender"}
  },
  "fixtures": [
    {
      "id": "<short unique id>",
      "family": "http | ftp | smb | ssh | privesc | lateral",
      "host": "ms3",
      "points": {"capture": 2, "block": 2, "remediate": 3},
      "flag": {"path": "/absolute/path/on/host", "owner": "root", "mode": "0444"},
      "keywords": ["words that map a defender's free-text claim to this fixture"],
      "check":  {"type": "<state-check name>", "...": "args"},
      "legit":  {"type": "<legit-probe name>", "...": "args"},
      "probe":  {"type": "<attacker-probe name>", "...": "args"}
    }
  ]
}
```

- **`family`** groups fixtures for reporting. Known families: http, ftp, smb, ssh, mysql, irc, privesc, lateral.
- **`scoring`** is "config" (fix-and-keep-up) or "exploit" (unpatchable; the race rule in scoring_policy.py). Default "config".
- **`flag`** is optional. A fixture with a flag is red-scorable (token planted there, re-issued each
  interval). A fixture with no flag is scored from the attacker-side `probe` only.
- **`check` / `legit` / `probe`** name the host-state check, the legitimate-service probe, and the
  attacker-side reachability probe. The available check types are the handlers already in
  `defender_verify.py` (`STATE_CHECKS`, `LEGIT_PROBES`) and `attacker_verify.py` (`PROBES`). A new
  fixture that needs a check none of those cover needs a new handler added there first — that handler
  is generic plumbing (run a read-only command, compare output); it is **not** the vulnerability.

## What goes in a fixture, and what does not

A fixture entry says **where the flag sits, and how to tell whether the weakness is open or closed**. It
does **not** contain the vulnerable configuration itself or any exploit steps. The weaknesses come from
the Metasploitable 3 image as published; the image is installed from Rapid7's build, not planted by this
repo. The scope docs likewise describe reachability and rules, never the exploit.

## Maxima

Derived from the set, never hand-typed:

- `red_max  = sum(points.capture for fixtures with a flag) [+ identify points if used]`
- `blue_max = sum(points.block + points.remediate for all fixtures) [+ identify]`
- per-interval: `tick_red_max = (#flag fixtures) x TICK_POINTS`, `tick_blue_max = (#fixtures) x TICK_POINTS`

Preregister these before comparative rounds and report them next to the scores.
