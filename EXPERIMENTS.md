# Running the remaining NEW section experiments

Implemented 28 October 2026. The trial manager produces separate attacker and defender scope files, prepares matched control conditions, runs the permitted SSH bridges for a fixed duration, and exports scores at the end. The human terminal uses the same attacker API and command limits. A human must actually operate it; no simulated human results are generated.

## Conditions

| Condition | Active participants | Purpose |
| --- | --- | --- |
| ai-versus-ai | Red and blue | Main adversarial trial |
| no-defender | Red only | Attacker baseline with no active repair |
| no-attacker | Blue only | Hardening and legitimate-service control |
| human-versus-ai | Human red and AI blue | Optional human comparison |
| service-control | Neither | Infrastructure and service baseline |

Prepare one of each for an initial pilot. Repeat independent trials before reporting comparative performance. Use the same frozen image, time limits, service requirements and disclosure policy. The research rationale and cited methodological limitations remain in RESEARCH.md. No-attacker detection scores are not comparable to attack detection scores: no attack occurred. A no-defender control still includes the baseline firewall and operating-system defenses.

## Preparation and launch

Run from the repository root using Python 3.11 or later. Protect the private directory with organizer-only filesystem permissions before preparation.

```powershell
python trials.py prepare pilot-human --condition human-versus-ai --seconds 1800
python scoring.py --db private/trials/pilot-human/score.db create pilot-human --seconds 86400 --output private/trials/pilot-human/flags.json
```

Restore the baseline, install the generated flags with install_flags.py, remove the transferred bundle from the VM, and verify their ownership and accessibility. Configure ssh_config as described in README.md. Inspect the generated red.json and blue.json, confirm addresses and authorized accounts, and test each SSH alias. The blue condition defaults to pfSense and Ubuntu-Weak; stock and IoT are excluded from this six-fixture experiment.

Record the baseline image hash, verification timestamp and flag-installation results in `flags-installed.txt` inside the trial folder. In trial.json, set `baseline_verified` and `connectivity_verified` true only after actually checking them. These are organizer attestations, not automated VM checks. The launcher refuses unverified trials, reused trial identifiers and already-started trials.

```powershell
python trials.py run private/trials/pilot-human
```

The launcher starts the clock at admission, updates the ledger expiry, starts only the permitted bridges, creates separate private red.token and blue.token files, and writes service logs. It terminates those bridges at the deadline and writes scores.json. Interruption also closes scoring. A bridge crash marks the trial interrupted. Expiry stops new API actions but does not forcibly terminate already-detached remote workloads; baseline restoration remains necessary.

In another terminal, launch the human interface:

```powershell
python human.py private/trials/pilot-human
```

For an AI participant, its trusted local adapter reads only its corresponding token and calls client.call as documented in OPERATOR_GUIDE.md. This package does not choose or call a model provider. Record inference requests with scoring.py prompt. Human actions appear in the red command audit but are not counted as model inference requests; compare human elapsed time and outcomes separately. Do not grant an AI general access to the trial directory.

For other conditions, substitute the condition and unique round name in the prepare command. Only run one trial at a time with the default ports. Before every control, close existing bridge processes and revoke previous participant sessions so a disabled role cannot continue acting through an old connection. Separate private directories isolate scores; they do not isolate VM state.

## Collection and interpretation

During each run, collect the scheduled legitimate-service samples and referee attestations using the existing scoring CLI. No-attacker and service-control runs require the same service measurements as the main trial. Zero raw score is expected in a service-only trial; availability is its meaningful outcome. Missing health samples yield an undefined availability-adjusted score, not a successful experiment.

Save all logs before reset. Record model identifiers, prompts, inference budgets, human experience, assistance, start time, endpoint configuration, image hash and interruptions. Scope documents generated in each trial folder are the participant handouts; review their addresses before release. Do not share private tokens or evidence with the opposing role.

The implementation has local tests, but no live trial, human participation, VM provisioning or AI-provider invocation was performed as part of this change. The manager supplies execution infrastructure; it cannot substitute for those observations.

