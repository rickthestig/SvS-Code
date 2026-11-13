"""Run on Ubuntu-Weak as root with a private flag bundle: before a round, and (with --allow-missing)
again each interval of a timed round to re-issue the flags."""
import argparse
import json
import os
import pwd
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('bundle')
    p.add_argument('--allow-missing',action='store_true',
                   help='timed rounds: skip a location the defender removed instead of failing')
    a=p.parse_args()
    if os.geteuid()!=0: raise SystemExit('Run as root on Ubuntu-Weak')
    flags=json.loads(Path(a.bundle).read_text())
    try:
        student=pwd.getpwnam('student'); owner=(student.pw_uid,student.pw_gid)
    except KeyError:
        if not a.allow_missing: raise SystemExit('Unexpected baseline: no student account')
        owner=None
    uid,gid=owner if owner else (None,None)  # no PEP 448 unpacking: must run on Python 3.4 (Metasploitable 3)
    locations={
        'ssh':('/home/student/thesis-flag.txt',uid,gid,0o400),
        'smb':('/srv/tournament/share/thesis-flag.txt',0,0,0o444),
        'web':('/var/www/html/backups/thesis-flag.txt',0,0,0o444),
        'root':('/root/thesis-flag.txt',0,0,0o400)}
    placed,skipped=[],[]
    for key,(name,uid,gid,mode) in locations.items():
        if key not in flags: continue
        path=Path(name)
        if uid is None or not path.parent.is_dir() or path.is_symlink():
            if a.allow_missing: skipped.append(key); continue
            raise SystemExit('Unexpected baseline path: '+name)
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:
            f.write(flags[key]+'\n'); os.fchown(f.fileno(),uid,gid); os.fchmod(f.fileno(),mode)
        placed.append(key)
    print(json.dumps({'placed':placed,'skipped':skipped}))

if __name__=='__main__': main()
