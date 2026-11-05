# Thesis lab scoring and AI access tools

The remaining outline NEW section is implemented in [EXPERIMENTS.md](EXPERIMENTS.md): `trials.py` prepares separate scopes and runs main/control conditions; `human.py` supplies the human-attacker interface.

This package implements a local scoring ledger and two independently authenticated HTTP to SSH bridges for the lab described in the thesis outline. Requires Python 3.11 or later and the OpenSSH client; no Python packages or model subscription are required. Run commands from this directory. The AI provider calls `client.call` through a local tool runner; a remote model API cannot directly reach your private VMs.

Read [the research and scoring specification](RESEARCH.md) before running a trial. This is a tested local prototype, not a live deployment. No VM, firewall, account, or running service was changed during development. Historical lab records supplied the example addresses; recheck them before use.

## Files

`scoring.py` manages rounds, flags, referee evidence, availability, and scores. `bridge.py` starts either the red or blue API. `client.py` provides the provider-neutral calling interface. `install_flags.py` places flags on Ubuntu-Weak. JSON and SSH examples describe the connection configuration. `tests/test_lab.py` tests the local behavior without contacting VMs.

## Prepare access

1. Restore the recorded target baseline and collect the actual IP addresses and package versions. Make a new snapshot before adding tournament accounts and flags. The existing records say Kali SSH is disabled, and temporary management links were removed. Merely starting this program will not create network reachability.
2. On Kali, enable its OpenSSH server for the experiment and install a dedicated red public key for `kali`. On Linux defenders, create a separate `defender` account and install a dedicated blue public key; grant the administrative operations required by the experimental condition. Do not reuse or disclose the existing organizer private key.
3. For pfSense, enable public-key-only SSH under System > Advanced > Admin Access. Add the defender public key through User Manager, grant shell access, and explicitly delegate required privileges. Normal shell access does not imply administrative privileges. See [Netgate's instructions](https://docs.netgate.com/pfsense/en/latest/recipes/ssh-access.html). Use its configuration mechanisms for persistent rule changes; transient `pfctl` edits alone are not a durable repair.
4. Create a dedicated management route or management jump host for the blue bridge and referee. Restrict it to the controller, and keep it unreachable from Kali and the participant networks. If using a jump host, add an organizer-configured `ProxyJump` entry and pin both host keys. Do not use Kali as the blue management jump host. Existing lab firewall rules permit specific Kali-to-target traffic; they do not establish this management plane.
5. Copy `ssh_config.example` to `ssh_config`; enter verified addresses, account names, and absolute private-key paths. Verify host-key fingerprints from each VM console before adding them to `~/.ssh/thesis_known_hosts`. `ssh-keyscan` alone does not authenticate a host. The bridge rejects unknown or changed host keys.
6. Check `ssh -F ssh_config thesis-kali id`, and the corresponding `thesis-weak`, `thesis-stock`, `thesis-iot`, and `thesis-pfsense` aliases. Remove targets from the blue JSON when they are outside the current experiment. Use separate controller OS accounts or containers for each model tool runner; neither model should have general shell or filesystem access to the organizer controller.

## Start a round

Create an organizer-only `private` directory. On Linux use mode 700 and umask 077; on Windows restrict its NTFS permissions to the organizer account. Keep private bundles, keys, the database, and logs out of participant prompts and shared folders. Each database round represents one red participant and one blue participant; use separate rounds for different pairings.

```powershell
python scoring.py create pilot-001 --seconds 1800 --output private/pilot-001-flags.json
```

Securely transfer that bundle and `install_flags.py` to a freshly restored Ubuntu-Weak. Run `sudo python3 install_flags.py /secure/path/pilot-001-flags.json` there, remove the transferred bundle immediately, and verify permissions. The organizer retains its private original. Do not copy the database to any participant VM. The installer expects the existing student, SMB, and Apache paths; it deliberately fails on a different baseline. Install before admitting participants. Setup time currently consumes the round window; allocate enough time or create the round immediately before installation and record the actual participant start time.

Create two independent random tokens in the PowerShell sessions used to run the respective bridges:

```powershell
$env:THESIS_RED_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
python bridge.py red.example.json
```

```powershell
$env:THESIS_BLUE_TOKEN = python -c "import secrets; print(secrets.token_urlsafe(32))"
python bridge.py blue.example.json
```

Give each trusted local model adapter only its corresponding token. Keep the same token available to its local tool runner. Both services bind only to localhost. To move a runner to another machine, use an authenticated encrypted tunnel with access controls; do not change this prototype to listen on a public interface.

## Connect any attacker or defender model API

Register a tool with the model provider that accepts `target` and `command`. Execute calls locally using this adapter:

```python
import os
from client import call
result = call(8765, os.environ['THESIS_RED_TOKEN'], 'execute',
              target='kali', command='id')
# Return result as the tool response to the attacker model.
result = call(8766, os.environ['THESIS_BLUE_TOKEN'], 'execute',
              target='weak', command='id')
# Defender targets can also be pfsense, stock, or iot if configured.
```

The attacker bridge allows only `kali`; the defender bridge allows its configured aliases. No caller can supply an IP, SSH username, key, or SSH option. Commands run in the remote shell with that account's privileges. Network containment must be enforced by the lab firewall: an SSH target allowlist does not constrain destinations of commands executed on Kali. Sessions are noninteractive and do not preserve working directory or shell variables across calls. Use `sudo -n` only when privileges were preconfigured. A command has a 30-second controller timeout and bounded output; killing SSH cannot guarantee that a detached remote process stops. Reset between trials and prohibit detached workloads in participant scope.

Capture and submit a flag:

```python
result = call(8765, os.environ['THESIS_RED_TOKEN'], 'submit',
              objective='ssh', token='FLAG{actual-captured-value}')
score = call(8765, os.environ['THESIS_RED_TOKEN'], 'score')
```

HTTP POST endpoints are `/execute`, `/submit` (red only), and `/score`. Use a JSON object and `Authorization: Bearer TOKEN`. Requests are limited to 16 KiB. HTTP 401 means authentication failed, 403 means forbidden target, 400 means invalid request or inactive round, and 503 means the organizer should inspect configuration. SSH exit status, stdout, stderr, timeout, and truncation are returned in the result. A successful HTTP status does not mean the remote command succeeded.

## Referee workflow

The trusted referee reviews evidence and uses the local CLI; models have no attestation endpoint. Save evidence as files with round, UTC time, challenge, vantage point, command/probe, output, expected result, actual result, and reviewer. Include the source log excerpt for identification. For a block, require exploit failure plus legitimate service success. For remediation, also require configuration evidence, re-test after service restart, and revocation of existing attacker access. Timeouts alone are inconclusive. See the verification matrix in RESEARCH.md.

```powershell
python scoring.py attest pilot-001 red ssh identify private/ssh-identification.json
python scoring.py attest pilot-001 blue ssh block private/ssh-block.json
python scoring.py attest pilot-001 blue ssh remediate private/ssh-repair.json
python scoring.py health pilot-001 tick-001 pass private/health-001.json
python scoring.py prompt pilot-001 red model-request-0001
python scoring.py report pilot-001
```

The tool hashes evidence files for later comparison but does not interpret their truth. Preserve original evidence. The referee controls the CLI and database, so this is not a tamper-proof ledger. Archive the closed-round database and evidence with a separately stored checksum manifest. Evidence corrections require a new corrected round or an explicitly documented database correction; there is no silent overwrite command.

Schedule health checks at fixed intervals (recommended 30 seconds) from a legitimate-client vantage point independent of Kali and the management plane. Record a failure for every scheduled missed/failed service tick. Record infrastructure outages separately and invalidate or repeat the round according to the preregistered rule; do not selectively omit unfavorable samples. The prototype records these samples but does not schedule or independently collect them. `blue_percent` remains null when no samples exist.

Count every model inference request, including planning, errors, and retries, through the organizer adapter using the `prompt` CLI or `Ledger.prompt`. Repeated recording of the same request ID is idempotent. This is not automatically inferred from SSH calls: one prompt can generate several commands. Compare prompt counts only after equal budgets and tied scores; report raw inference counts, tokens, cost, elapsed time, and intervention count separately.

## Local verification

```powershell
python -m unittest discover -s tests -v
```

Tests cover flag rejection, duplicate and cross-round submissions, expiry, score maxima, availability adjustment, prompt deduplication, SSH argument validation, HTTP authentication, target rejection, and a mocked command path. They do not verify live connectivity, flag installation, pfSense permissions, actual repairs, or model-provider integration.

