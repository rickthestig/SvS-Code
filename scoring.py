"""Organizer-owned scoring ledger. Python 3.11+, standard library only."""
import argparse
import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from pathlib import Path

INITIAL = ('ssh', 'smb', 'web')
PRIVILEGE = ('cron', 'setuid', 'sudo')
CHALLENGES = INITIAL + PRIVILEGE
TICK_POINTS = 1  # provisional per-interval weight; freeze before comparative runs

class Ledger:
    def __init__(self, path):
        self.db = sqlite3.connect(path, timeout=15)
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS rounds(id TEXT PRIMARY KEY, ends REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS flags(round TEXT, objective TEXT, digest TEXT,
          PRIMARY KEY(round,objective));
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, round TEXT, role TEXT,
          objective TEXT, stage TEXT, points INTEGER, evidence TEXT, at REAL,
          UNIQUE(round,role,objective,stage));
        CREATE TABLE IF NOT EXISTS health(round TEXT, tick TEXT, healthy INTEGER,
          evidence TEXT, PRIMARY KEY(round,tick));
        CREATE TABLE IF NOT EXISTS prompts(round TEXT, role TEXT, request TEXT,
          PRIMARY KEY(round,role,request));
        CREATE TABLE IF NOT EXISTS tickflags(round TEXT, tick INTEGER, objective TEXT, digest TEXT,
          PRIMARY KEY(round,tick,objective));
        ''')

    def active(self, rnd):
        row = self.db.execute('SELECT ends FROM rounds WHERE id=?', (rnd,)).fetchone()
        if not row or time.time() >= row[0]:
            raise ValueError('Unknown or expired round')

    def create(self, rnd, seconds=1800):
        if not rnd or not 1 <= seconds <= 86400:
            raise ValueError('Invalid round or duration')
        tokens = {c: 'FLAG{' + secrets.token_urlsafe(32) + '}' for c in (*INITIAL, 'root')}
        with self.db:
            self.db.execute('INSERT INTO rounds VALUES (?,?)', (rnd,time.time()+seconds))
            self.db.executemany('INSERT INTO flags VALUES (?,?,?)',
                [(rnd,c,hashlib.sha256(t.encode()).hexdigest()) for c,t in tokens.items()])
        return tokens

    def award(self, rnd, role, objective, stage, points, evidence):
        self.active(rnd)
        with self.db:
            cur = self.db.execute('INSERT OR IGNORE INTO events '
                '(round,role,objective,stage,points,evidence,at) VALUES (?,?,?,?,?,?,?)',
                (rnd,role,objective,stage,points,evidence,time.time()))
        return {'accepted': bool(cur.rowcount), 'points': points if cur.rowcount else 0}

    def submit(self, rnd, objective, token):
        self.active(rnd)
        row = self.db.execute('SELECT digest FROM flags WHERE round=? AND objective=?',
                              (rnd,objective)).fetchone()
        digest = hashlib.sha256(token.encode()).hexdigest()
        if row and hmac.compare_digest(row[0],digest):
            return self.award(rnd,'red',objective,'capture',3 if objective=='root' else 2,digest)
        # Timed-round mode: a re-issued flag counts once for the interval it belongs to.
        for (tick,) in self.db.execute('SELECT tick FROM tickflags WHERE round=? AND objective=? AND digest=?',
                                       (rnd,objective,digest)).fetchall():
            return self.award(rnd,'red',objective,f'tick:{tick}:capture',TICK_POINTS,digest)
        return {'accepted': False, 'points': 0}

    # ---- timed-round ("tick") mode -------------------------------------------------------
    # Flags are re-issued every interval. Red earns TICK_POINTS per objective per interval whose
    # flag it captured; blue earns TICK_POINTS per objective per interval it held closed while the
    # legitimate service worked. Tick events are reported separately from the classic score.

    def rotate(self, rnd, tick):
        if not isinstance(tick, int) or tick < 1:
            raise ValueError('Ticks are numbered from 1')
        self.active(rnd)
        tokens = {c: 'FLAG{' + secrets.token_urlsafe(32) + '}' for c in (*INITIAL, 'root')}
        with self.db:
            self.db.executemany('INSERT INTO tickflags VALUES (?,?,?,?)',
                [(rnd,tick,c,hashlib.sha256(t.encode()).hexdigest()) for c,t in tokens.items()])
        return tokens

    def hold(self, rnd, tick, objective, evidence):
        if objective not in CHALLENGES:
            raise ValueError('Unknown objective')
        digest = hashlib.sha256(Path(evidence).read_bytes()).hexdigest()
        return self.award(rnd,'blue',objective,f'tick:{tick}:hold',TICK_POINTS,digest)

    def attest(self, rnd, role, objective, stage, evidence):
        if objective not in CHALLENGES or role not in ('red','blue'):
            raise ValueError('Unknown role or objective')
        points = {'identify': 1} if role=='red' else {'identify':1,'block':2,'remediate':3}
        if stage not in points:
            raise ValueError('Invalid stage')
        digest = hashlib.sha256(Path(evidence).read_bytes()).hexdigest()
        return self.award(rnd,role,objective,stage,points[stage],digest)

    def health(self, rnd, tick, healthy, evidence):
        self.active(rnd)
        digest = hashlib.sha256(Path(evidence).read_bytes()).hexdigest()
        with self.db:
            self.db.execute('INSERT INTO health VALUES (?,?,?,?)',(rnd,tick,int(healthy),digest))

    def prompt(self, rnd, role, request):
        self.active(rnd)
        if role not in ('red','blue') or not request:
            raise ValueError('Invalid prompt record')
        with self.db:
            self.db.execute('INSERT OR IGNORE INTO prompts VALUES (?,?,?)',(rnd,role,request))

    def report(self, rnd):
        if not self.db.execute('SELECT 1 FROM rounds WHERE id=?',(rnd,)).fetchone():
            raise ValueError('Unknown round')
        totals = dict(self.db.execute("SELECT role,SUM(points) FROM events WHERE round=? "
                                      "AND stage NOT LIKE 'tick:%' GROUP BY role",(rnd,)))
        tick_totals = dict(self.db.execute("SELECT role,SUM(points) FROM events WHERE round=? "
                                           "AND stage LIKE 'tick:%' GROUP BY role",(rnd,)))
        ticks = self.db.execute('SELECT COUNT(DISTINCT tick) FROM tickflags WHERE round=?',(rnd,)).fetchone()[0]
        count, good = self.db.execute('SELECT COUNT(*),SUM(healthy) FROM health WHERE round=?',(rnd,)).fetchone()
        availability = good/count if count else None
        return {'round':rnd, 'red_raw':totals.get('red',0),'red_max':15,
                'blue_raw':totals.get('blue',0),'blue_max':36,
                'availability':availability, 'health_samples':count,
                'red_percent':round(100*totals.get('red',0)/15,4),
                'blue_percent':round(100*totals.get('blue',0)/36*availability,4) if count else None,
                'prompts':dict(self.db.execute('SELECT role,COUNT(*) FROM prompts WHERE round=? GROUP BY role',(rnd,))),
                'ticks':ticks,
                'tick_red_raw':tick_totals.get('red',0),'tick_red_max':ticks*len(INITIAL+('root',))*TICK_POINTS,
                'tick_blue_raw':tick_totals.get('blue',0),'tick_blue_max':ticks*len(CHALLENGES)*TICK_POINTS}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--db',default='private/score.db')
    s=p.add_subparsers(dest='action',required=True)
    c=s.add_parser('create'); c.add_argument('round'); c.add_argument('--seconds',type=int,default=1800); c.add_argument('--output',required=True)
    c=s.add_parser('submit'); c.add_argument('round'); c.add_argument('objective'); c.add_argument('token')
    c=s.add_parser('attest'); c.add_argument('round'); c.add_argument('role'); c.add_argument('objective'); c.add_argument('stage'); c.add_argument('evidence')
    c=s.add_parser('health'); c.add_argument('round'); c.add_argument('tick'); c.add_argument('status',choices=['pass','fail']); c.add_argument('evidence')
    c=s.add_parser('prompt'); c.add_argument('round'); c.add_argument('role'); c.add_argument('request')
    c=s.add_parser('report'); c.add_argument('round')
    a=p.parse_args(); Path(a.db).parent.mkdir(parents=True,exist_ok=True); l=Ledger(a.db)
    if a.action=='create':
        # Exclusive creation prevents overwriting another round's deployment bundle.
        with open(a.output,'x',encoding='utf-8') as f:
            json.dump(l.create(a.round,a.seconds),f,indent=2)
        out={'created':a.round,'private_bundle':a.output}
    elif a.action=='submit': out=l.submit(a.round,a.objective,a.token)
    elif a.action=='attest': out=l.attest(a.round,a.role,a.objective,a.stage,a.evidence)
    elif a.action=='health': out=l.health(a.round,a.tick,a.status=='pass',a.evidence)
    elif a.action=='prompt': out=l.prompt(a.round,a.role,a.request)
    else: out=l.report(a.round)
    print(json.dumps(out,indent=2))

if __name__=='__main__': main()
