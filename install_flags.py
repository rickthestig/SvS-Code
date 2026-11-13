"""Plant the round's flag tokens on a target, before a round and (with --allow-missing) each interval.

Two bundle formats, auto-detected:
  * legacy flat {key: token}        -> planted at the hardcoded Ubuntu-Weak locations below.
  * {"_format":"fixture","flags":{key:token},"locations":{key:{path,owner,mode}}}
                                    -> planted at the fixture set's own paths (any host/cohort).

Runs as root on the target. Must stay Python 3.4-compatible (Metasploitable 3 ships 3.4):
no f-strings, no * unpacking in literals, no walrus."""
import argparse
import json
import os
import pwd
from pathlib import Path

LEGACY = {  # Ubuntu-Weak, used when the bundle is a flat {key: token}
    "ssh": ("/home/student/thesis-flag.txt", "student", "0400"),
    "smb": ("/srv/tournament/share/thesis-flag.txt", "root", "0444"),
    "web": ("/var/www/html/backups/thesis-flag.txt", "root", "0444"),
    "root": ("/root/thesis-flag.txt", "root", "0400"),
}


def resolve_owner(name):
    if name in (None, "root"):
        return (0, 0)
    p = pwd.getpwnam(name)
    return (p.pw_uid, p.pw_gid)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("bundle")
    ap.add_argument("--allow-missing", action="store_true",
                    help="skip a location whose parent dir or owner is absent instead of failing")
    a = ap.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Run as root on the target")
    with open(a.bundle) as fh:  # Path.read_text() is 3.5+; this runs on Metasploitable's Python 3.4
        data = json.loads(fh.read())
    if isinstance(data, dict) and data.get("_format") == "fixture":
        flags = data["flags"]
        locs = data["locations"]
        locations = dict((k, (locs[k]["path"], locs[k].get("owner", "root"), locs[k].get("mode", "0444")))
                         for k in flags if k in locs)
    else:
        flags, locations = data, LEGACY

    placed, skipped = [], []
    for key, token in flags.items():
        if key not in locations:
            skipped.append(key)
            continue
        name, owner, mode = locations[key]
        path = Path(name)
        try:
            uid, gid = resolve_owner(owner)
        except KeyError:
            if a.allow_missing:
                skipped.append(key)
                continue
            raise SystemExit("Unknown owner for " + key + ": " + str(owner))
        if not path.parent.is_dir() or path.is_symlink() or name in ("TODO", ""):
            if a.allow_missing:
                skipped.append(key)
                continue
            raise SystemExit("Unexpected baseline path: " + name)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(token + "\n")
            os.fchown(f.fileno(), uid, gid)
            os.fchmod(f.fileno(), int(mode, 8))
        placed.append(key)
    print(json.dumps({"placed": placed, "skipped": skipped}))


if __name__ == "__main__":
    main()
