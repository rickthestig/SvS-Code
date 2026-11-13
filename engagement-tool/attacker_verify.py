#!/usr/bin/env python3
"""
Attacker-side verifier. Runs from the attacker vantage point (Kali) against the defender's
target, in two steps:

  1. CONNECTIVITY: confirms the target is reachable from the attacker at all, per service port.
     A closed/unreachable port could mean "fixed" or "host down" -- recording reachability of the
     other services lets the referee tell those apart (failed access is not proof of repair).
  2. PER-OBJECTIVE PROBES: re-runs the same *non-destructive* access check the red side used
     (does SSH still offer password auth? does the SMB share allow guest? is the backup file served?)
     and records status = open | closed | not_probeable, with the raw observed output.

Run it once BEFORE the defender acts (--label pre) and once AFTER (--label post). A `closed`
result only counts toward credit if the pre run shows it was `open`, so a defender cannot be
rewarded for "fixing" something that was never exposed.

Probes only test access that the lab's own fixtures expose; they run no exploits and change nothing.
cron / setuid / sudo are local-privilege issues: what matters is what the low-privilege user can
do once on the box. By default they are probed ON the target, running each check as that user
(`sudo -u student` from the operator's session) -- so they still work after the defender changes
or locks the student password. Supplying "lowpriv" credentials in probes.json probes them from
Kali over SSH instead. If neither works they report not_probeable.

Usage:
    python attacker_verify.py --label pre|post --out attacker-<label>.json [--probes probes.json]
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

DEFAULT_PROBES = {
    "target_ip": "10.10.30.20",
    "ports": {"ssh": 22, "smb": 445, "web": 80},
    "smb_share": "public",
    "web_paths": ["/backups/device-config.txt"],
    # The low-privilege fixture account the cron/setuid/sudo probes run as (on-host by default).
    "lowpriv_user": "student",
    # Optional: probe from Kali over SSH with a password instead, e.g.
    # "lowpriv": {"user": "student", "password": "<lab fixture password>"}
}


def kali(client, cmd, timeout=40):
    import engagement_common as ec
    return ec.run(client, cmd, timeout=timeout)


def connectivity(client, ip, ports):
    res = {}
    for name, port in ports.items():
        rc, out, _ = kali(client, f"timeout 5 bash -c 'echo > /dev/tcp/{ip}/{int(port)}' && echo OPEN || echo CLOSED")
        res[name] = {"port": port, "reachable": "OPEN" in out}
    return res


def probe_ssh(client, ip, cfg):
    cmd = (f"ssh -o PreferredAuthentications=none -o BatchMode=yes -o ConnectTimeout=6 "
           f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null nobody@{ip} true 2>&1 | tail -3")
    rc, out, _ = kali(client, cmd)
    m = re.search(r"Permission denied \(([^)]*)\)", out)
    if not m:
        return {"status": "not_probeable", "observed": out.strip()}
    methods = m.group(1).split(",")
    return {"status": "open" if "password" in methods else "closed",
            "observed": f"auth methods offered: {methods}"}


def probe_smb(client, ip, cfg):
    share = shlex.quote(cfg["smb_share"])
    rc, out, _ = kali(client, f"timeout 20 smbclient //{ip}/{share} -N -c ls 2>&1 | tail -6")
    if re.search(r"NT_STATUS_(ACCESS_DENIED|LOGON_FAILURE|BAD_NETWORK_NAME)", out):
        return {"status": "closed", "observed": out.strip()[-300:]}
    if re.search(r"blocks available|\bD\s+0\b|\s+A\s+\d+", out):
        return {"status": "open", "observed": out.strip()[-300:]}
    return {"status": "not_probeable", "observed": out.strip()[-300:]}


def probe_web(client, ip, cfg):
    codes = {}
    for path in cfg["web_paths"]:
        rc, out, _ = kali(client, f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 8 "
                                  f"{shlex.quote('http://' + ip + path)}")
        codes[path] = out.strip()
    if all(c == "000" for c in codes.values()):
        return {"status": "not_probeable", "observed": codes}
    return {"status": "open" if any(c == "200" for c in codes.values()) else "closed", "observed": codes}


def _lowpriv(client, ip, cfg, remote_cmd):
    """Run remote_cmd as the low-privilege user; None if that isn't possible."""
    lp = cfg.get("lowpriv")
    if lp:
        cmd = (f"SSHPASS={shlex.quote(lp['password'])} sshpass -e ssh -o StrictHostKeyChecking=no "
               f"-o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 {shlex.quote(lp['user'])}@{ip} "
               f"{shlex.quote(remote_cmd)} 2>&1 | tail -15")
        return kali(client, cmd, timeout=60)[1]
    host = cfg.get("_host")
    if host is None:
        return None
    user = shlex.quote(cfg.get("lowpriv_user", "student"))
    return kali(host, f"sudo -n -u {user} -- bash -c {shlex.quote(remote_cmd)} 2>&1 | tail -15", timeout=60)[1]


def _need_lowpriv(out):
    return out is None or "Permission denied" in out or "sshpass" in out and "not found" in out


def open_host_probe(cfg):
    """Operator session on the target that can act as the low-privilege user, or None."""
    import engagement_common as ec
    try:
        host = ec.target_ssh(cfg["target_ip"])
    except Exception:  # noqa: BLE001
        return None
    user = shlex.quote(cfg.get("lowpriv_user", "student"))
    _, out, _ = ec.run(host, f"sudo -n -u {user} -- true && echo AS_USER_OK")
    if "AS_USER_OK" not in out:
        host.close()
        return None
    return host


def probe_sudo(client, ip, cfg):
    out = _lowpriv(client, ip, cfg, "sudo -n -l")
    if _need_lowpriv(out):
        return {"status": "not_probeable", "observed": "no working lowpriv login in probes.json"}
    bad = bool(re.search(r"NOPASSWD|\(ALL(\s*:\s*ALL)?\)\s+ALL", out))
    return {"status": "open" if bad else "closed", "observed": out.strip()[-300:]}


def probe_setuid(client, ip, cfg):
    out = _lowpriv(client, ip, cfg, "find /usr/local /opt /srv /home /tmp -xdev -perm -4000 -type f 2>/dev/null")
    if _need_lowpriv(out):
        return {"status": "not_probeable", "observed": "no working lowpriv login in probes.json"}
    found = [l for l in out.splitlines() if l.startswith("/")]
    return {"status": "open" if found else "closed", "observed": found or "none"}


def probe_cron(client, ip, cfg):
    out = _lowpriv(client, ip, cfg, "find /etc/cron.d /etc/cron.daily /usr/local/bin /usr/local/sbin /opt "
                                    "-xdev -type f -writable 2>/dev/null")
    if _need_lowpriv(out):
        return {"status": "not_probeable", "observed": "no working lowpriv login in probes.json"}
    found = [l for l in out.splitlines() if l.startswith("/")]
    return {"status": "open" if found else "closed", "observed": found or "none"}


PROBES = {"ssh": probe_ssh, "smb": probe_smb, "web": probe_web,
          "cron": probe_cron, "setuid": probe_setuid, "sudo": probe_sudo}


def probe_all(label: str, overrides: dict | None = None) -> dict:
    """Connectivity + every objective probe; returns the report dict (also used per interval in
    timed rounds)."""
    cfg = dict(DEFAULT_PROBES)
    cfg.update(overrides or {})
    import engagement_common as ec
    client = ec.kali_ssh()
    cfg["_host"] = None if cfg.get("lowpriv") else open_host_probe(cfg)
    try:
        conn = connectivity(client, cfg["target_ip"], cfg["ports"])
        results = {obj: fn(client, cfg["target_ip"], cfg) for obj, fn in PROBES.items()}
    finally:
        client.close()
        if cfg["_host"] is not None:
            cfg["_host"].close()
    local_vantage = ("kali-ssh-as-" + cfg["lowpriv"]["user"] if cfg.get("lowpriv")
                     else f"on-host-as-{cfg.get('lowpriv_user', 'student')}")
    for obj in ("cron", "setuid", "sudo"):
        results[obj]["vantage"] = local_vantage
    return {"label": label, "target_ip": cfg["target_ip"], "vantage": "kali (network probes)",
            "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "connectivity": conn, "objectives": results}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--label", required=True, choices=["pre", "post"])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--probes", type=pathlib.Path, help="JSON overriding DEFAULT_PROBES")
    a = ap.parse_args()

    overrides = json.loads(a.probes.read_text(encoding="utf-8")) if a.probes else None
    report = probe_all(a.label, overrides)
    a.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    conn, results = report["connectivity"], report["objectives"]
    print("connectivity:", {k: ("up" if v["reachable"] else "DOWN") for k, v in conn.items()})
    for obj, r in results.items():
        print(f"  {obj:7s} {r['status']:14s} {str(r['observed'])[:110]}")
    print(f"-> {a.out}")


if __name__ == "__main__":
    main()
