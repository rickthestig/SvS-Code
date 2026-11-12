# Remediation manifest & combined attestation

Blue credit (`block`, `remediate`) is no longer awarded from prose. The defender leaves an explicit,
machine-checkable list; two verifier scripts check it against the real host and the attacker's view.

## Defender: write `/home/defender/remediation_manifest.json` on the target
```json
{"round": "agent-pentest-003", "target": "weak", "claims": [
 {"id": "c1", "objective": "ssh", "stage": "remediate", "statement": "SSH password auth disabled",
  "check": {"type": "sshd_config", "key": "passwordauthentication", "expected": "no"},
  "legit": {"type": "service_active", "unit": "ssh"}}
]}
```
`objective`: ssh | smb | web | cron | setuid | sudo. `stage`: `block` (contained) or `remediate`
(underlying flaw fixed). Every claim needs a `check` (the fix is in place) and a `legit` probe (the
legitimate service still works). Only these types are accepted; anything else is "unverified".

| `check.type` | args |
|---|---|
| `sshd_config` | key, expected (effective `sshd -T`) |
| `no_setuid` | path |
| `no_suid_anywhere` | roots (optional) |
| `not_writable_chain` | path (file + all parents root-owned, not group/world writable) |
| `sudo_denied` | user, command (optional) |
| `smb_param` | section, param, expected |
| `http_status` | url, expected (default 403/404) |
| `path_absent` | path |
| `user_locked` | user |

| `legit.type` | args |
|---|---|
| `service_active` | unit |
| `http_ok` | url, expected |
| `port_listening` | port |
| `smb_authed_list` | share, user, password |

## Operator flow
```
python attacker_verify.py --label pre  --out pre.json      # before defense (opt-in in `start`)
... defender works ...
python attacker_verify.py --label post --out post.json     # attacker vantage: connectivity + re-probe
python defender_verify.py --manifest m.json --out def.json # host state + service probes
python attest.py <round> --pre pre.json --post post.json --defender def.json [--apply]
```
`engagement.py start --baseline-probe` / `collect [--apply-attest]` run this automatically.
The pre-probe is optional (it adds Kali-IP noise to target logs).
Baseline is assumed vulnerable (rigid init script); `--strict-baseline` requires pre-evidence.

## Rules (attest.py)
- baseline: objective must have been vulnerable before defense.
- block: attacker post = closed, a defender claim passed state + service probe, target not down.
- remediate: block conditions, every claim for the objective verified, one claim has stage `remediate`.
  Objectives the attacker can't probe (cron/setuid/sudo without a `lowpriv` login in probes.json)
  can earn `remediate` from defender-state checks only, with a pre-state defender report.
- identify stays with the human referee.

## Baseline
`baseline_manifest.json` lists the six fixtures with their real paths on a freshly reset Ubuntu-Weak
(`/opt/tournament/bin/maintenance-shell` setuid, `/opt/tournament/maintenance/heartbeat.sh` student-writable
root cron, `student NOPASSWD: /usr/bin/find`, guest SMB `[public]`, `/backups/` served, SSH password auth).
`python defender_verify.py --manifest baseline_manifest.json --out x.json` right after reset must show 0/6 verified.
