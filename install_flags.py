"""Run on Ubuntu-Weak as root, before a round, with a private flag bundle."""
import argparse
import json
import os
import pwd
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('bundle'); a=p.parse_args()
    if os.geteuid()!=0: raise SystemExit('Run as root on Ubuntu-Weak')
    flags=json.loads(Path(a.bundle).read_text())
    student=pwd.getpwnam('student')
    locations={
        'ssh':('/home/student/thesis-flag.txt',student.pw_uid,student.pw_gid,0o400),
        'smb':('/srv/tournament/share/thesis-flag.txt',0,0,0o444),
        'web':('/var/www/html/backups/thesis-flag.txt',0,0,0o444),
        'root':('/root/thesis-flag.txt',0,0,0o400)}
    for key,(name,uid,gid,mode) in locations.items():
        path=Path(name)
        if not path.parent.is_dir() or path.is_symlink():
            raise SystemExit('Unexpected baseline path: '+name)
        # Before participants run, on a freshly restored baseline only.
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:
            f.write(flags[key]+'\n'); os.fchown(f.fileno(),uid,gid); os.fchmod(f.fileno(),mode)
    print('Installed four flags. Remove the private bundle from the target before participants connect.')

if __name__=='__main__': main()
