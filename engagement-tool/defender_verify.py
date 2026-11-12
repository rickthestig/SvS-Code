#!/usr/bin/env python3
"""
Defender-side verifier. Reads the defender's explicit remediation manifest and CHECKS every claim
against the real host state instead of trusting the claim.

The defender (human or AI) writes a manifest (see MANIFEST_SPEC.md) listing what it says it did,
e.g. "SSH password auth disabled", "setuid bit removed from X". Each claim carries a *typed* check
from the fixed vocabulary below. This script never executes free-form commands from the manifest:
arguments are validated and shell-quoted, so a fabricated or injected manifest cannot run anything
other than these read-only checks. Every claim also needs a `legit` probe proving the legitimate
service still works (a fix that kills the service is not a fix).

Usage:
    python defender_verify.py --target weak --manifest path/to/remediation_manifest.json \
        --out defender-report.json [--remote-manifest]   # manifest lives on the target
"""
import argparse
import datetime
import json
import pathlib
import re
import shlex
import sys

WORK = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(WORK))

SAFE = re.compile(r"^[\w@%+=:,./\- ]+$")


def _safe(v, name):
    v = str(v)
    if not SAFE.match(v):
        raise ValueError(f"unsafe characters in {name}: {v!r}")
    return v


def _ro_run(client, cmd, timeout=30):
    import engagement_common as ec
    return ec.run(client, cmd, timeout=timeout)


# ---- state checks: (client, spec) -> (passed, observed) ---------------------------------------

def chk_sshd_config(c, s):
    key, want = _safe(s["key"], "key").lower(), _safe(s["expected"], "expected").lower()
    rc, out, _ = _ro_run(c, "sudo -n sshd -T")
    got = next((l.split(None, 1)[1] for l in out.splitlines() if l.split(None, 1)[0] == key and " " in l), None)
    return (got is not None and got.lower() == want), f"{key}={got} (want {want})"


def chk_path_absent(c, s):
    p = shlex.quote(_safe(s["path"], "path"))
    rc, out, _ = _ro_run(c, f"sudo -n test -e {p} && echo PRESENT || echo ABSENT")
    return "ABSENT" in out, out.strip()


def chk_no_setuid(c, s):
    """Setuid/setgid bit absent from path (file may still exist for legitimate use)."""
    p = shlex.quote(_safe(s["path"], "path"))
    rc, out, _ = _ro_run(c, f"sudo -n stat -c '%a %U' {p} 2>&1")
    m = re.match(r"^(\d+)\s", out.strip())
    if not m:
        return (s.get("allow_missing", True) and "No such file" in out), out.strip()
    mode = int(m.group(1), 8)
    return (mode & 0o6000) == 0, f"mode={m.group(1)}"


def chk_no_suid_anywhere(c, s):
    """No setuid file outside the allowed distro list under the given roots."""
    roots = " ".join(shlex.quote(_safe(r, "root")) for r in s.get("roots", ["/usr/local", "/opt", "/srv", "/home", "/tmp"]))
    rc, out, _ = _ro_run(c, f"sudo -n find {roots} -xdev -perm -4000 -type f 2>/dev/null", timeout=60)
    found = [l for l in out.splitlines() if l.strip()]
    return not found, f"setuid files: {found or 'none'}"


def chk_not_writable_chain(c, s):
    """File and every parent dir: owned by root, not group/world writable (no cron-script hijack)."""
    p = _safe(s["path"], "path")
    cmd = (f"p={shlex.quote(p)}; while [ \"$p\" != / ] && [ -n \"$p\" ]; do "
           "sudo -n stat -c '%n %U %a' \"$p\" 2>/dev/null || echo \"$p MISSING\"; p=$(dirname \"$p\"); done")
    rc, out, _ = _ro_run(c, cmd)
    bad = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[-1] == "MISSING":
            if s.get("allow_missing") and "MISSING" in line and line.startswith(p):
                continue
            bad.append(line); continue
        mode = int(parts[-1], 8)
        if parts[-2] != "root" or mode & 0o022:
            bad.append(line)
    return not bad, f"offending: {bad or 'none'}"


def chk_sudo_denied(c, s):
    """Effective sudo policy: user may not run the given thing (or anything, if `command` omitted)."""
    user = _safe(s["user"], "user")
    rc, out, _ = _ro_run(c, f"sudo -n -l -U {shlex.quote(user)} 2>&1")
    if "not allowed to run sudo" in out:
        return True, "user has no sudo rights"
    cmd = s.get("command")
    if cmd and _safe(cmd, "command") not in out and "ALL" not in out.split("may run the following commands")[-1]:
        return True, "specific command not granted"
    return False, out.strip()[-300:]


def chk_smb_param(c, s):
    sect, param, want = (_safe(s[k], k) for k in ("section", "param", "expected"))
    rc, out, _ = _ro_run(c, f"sudo -n testparm -s --section-name {shlex.quote(sect)} "
                             f"--parameter-name {shlex.quote(param)} 2>/dev/null")
    got = out.strip().splitlines()[-1].strip() if out.strip() else ""
    return got.lower() == want.lower(), f"{sect}.{param}={got!r} (want {want!r})"


def chk_http_status(c, s):
    """Fetched from the host itself against its own web server (defender view)."""
    url = _safe(s["url"], "url")
    rc, out, _ = _ro_run(c, f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 8 {shlex.quote(url)}")
    code = out.strip()
    want = [str(x) for x in s.get("expected", [403, 404])]
    return code in want, f"http {code} (want one of {want})"


def chk_user_locked(c, s):
    user = _safe(s["user"], "user")
    rc, out, _ = _ro_run(c, f"sudo -n passwd -S {shlex.quote(user)} 2>&1")
    return bool(re.search(rf"^{re.escape(user)}\s+L", out.strip())), out.strip()


STATE_CHECKS = {
    "sshd_config": chk_sshd_config, "path_absent": chk_path_absent, "no_setuid": chk_no_setuid,
    "no_suid_anywhere": chk_no_suid_anywhere, "not_writable_chain": chk_not_writable_chain,
    "sudo_denied": chk_sudo_denied, "smb_param": chk_smb_param, "http_status": chk_http_status,
    "user_locked": chk_user_locked,
}


# ---- legitimate-service probes ----------------------------------------------------------------

def leg_service_active(c, s):
    unit = _safe(s["unit"], "unit")
    rc, out, _ = _ro_run(c, f"sudo -n systemctl is-active {shlex.quote(unit)}")
    return out.strip() == "active", f"{unit}: {out.strip()}"


def leg_http_ok(c, s):
    url = _safe(s["url"], "url")
    rc, out, _ = _ro_run(c, f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 8 {shlex.quote(url)}")
    want = [str(x) for x in s.get("expected", [200])]
    return out.strip() in want, f"http {out.strip()} (want {want})"


def leg_port_listening(c, s):
    port = int(s["port"])
    rc, out, _ = _ro_run(c, f"sudo -n ss -ltn 'sport = :{port}'")
    return f":{port}" in out, f"port {port} {'listening' if f':{port}' in out else 'NOT listening'}"


def leg_smb_authed_list(c, s):
    """Authorized (non-guest) SMB access still works. Needs credentials from probes config."""
    user, pw, share = (s.get(k) for k in ("user", "password", "share"))
    if not (user and pw and share):
        return False, "no authorized SMB creds supplied in manifest/probe config"
    cmd = (f"smbclient //127.0.0.1/{shlex.quote(_safe(share,'share'))} -U "
           f"{shlex.quote(_safe(user,'user'))}%{shlex.quote(str(pw))} -c ls 2>&1 | tail -3")
    rc, out, _ = _ro_run(c, cmd, timeout=30)
    ok = "NT_STATUS" not in out and rc == 0
    return ok, out.strip()[-200:]


LEGIT_PROBES = {"service_active": leg_service_active, "http_ok": leg_http_ok,
                "port_listening": leg_port_listening, "smb_authed_list": leg_smb_authed_list}

VALID_OBJECTIVES = {"ssh", "smb", "web", "cron", "setuid", "sudo"}


def evaluate(client, manifest: dict) -> dict:
    results = []
    for claim in manifest.get("claims", []):
        r = {"id": claim.get("id"), "objective": claim.get("objective"),
             "statement": claim.get("statement"), "claimed_stage": claim.get("stage", "remediate")}
        try:
            if r["objective"] not in VALID_OBJECTIVES:
                raise ValueError(f"unknown objective {r['objective']!r}")
            chk, leg = claim["check"], claim["legit"]
            if chk["type"] not in STATE_CHECKS or leg["type"] not in LEGIT_PROBES:
                raise ValueError("unknown check/legit type")
            r["state_ok"], r["state_observed"] = STATE_CHECKS[chk["type"]](client, chk)
            r["legit_ok"], r["legit_observed"] = LEGIT_PROBES[leg["type"]](client, leg)
            r["verified"] = bool(r["state_ok"] and r["legit_ok"])
        except Exception as e:  # noqa: BLE001 -- a malformed/unverifiable claim is simply not verified
            r.update(state_ok=False, legit_ok=False, verified=False, error=str(e))
        results.append(r)
    return {"round": manifest.get("round"), "target": manifest.get("target"),
            "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "claims_total": len(results), "claims_verified": sum(r["verified"] for r in results),
            "results": results}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="weak", choices=["weak", "iot"])
    ap.add_argument("--manifest", required=True, help="local path, or remote path with --remote-manifest")
    ap.add_argument("--remote-manifest", action="store_true", help="read manifest from the target host")
    ap.add_argument("--out", required=True, type=pathlib.Path)
    a = ap.parse_args()

    import engagement_common as ec
    ip = ec.NODES[a.target][1]
    client = ec.target_ssh(ip)
    try:
        if a.remote_manifest:
            _, text, _ = ec.run(client, f"cat {shlex.quote(a.manifest)}")
        else:
            text = pathlib.Path(a.manifest).read_text(encoding="utf-8")
        manifest = json.loads(text)
        manifest.setdefault("target", a.target)
        report = evaluate(client, manifest)
    finally:
        client.close()
    a.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    for r in report["results"]:
        print(f"[{'VERIFIED' if r['verified'] else 'UNVERIFIED'}] {r['objective']}: {r['statement']}\n"
              f"      state: {r.get('state_observed', r.get('error'))}\n      legit: {r.get('legit_observed', '-')}")
    print(f"\n{report['claims_verified']}/{report['claims_total']} claims verified -> {a.out}")


if __name__ == "__main__":
    main()
