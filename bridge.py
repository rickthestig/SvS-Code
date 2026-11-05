"""Role-specific loopback HTTP to SSH bridge, independent of LLM vendor."""
import argparse
import hashlib
import hmac
import json
import os
import platform
import subprocess
import tempfile
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from scoring import Ledger

def config_path(path):
    # Windows OpenSSH's -F argument parser mishandles a config path that
    # contains a space (reproducibly: 'hostname contains invalid characters'),
    # which bites here whenever the project lives under a directory like
    # 'a workspace with spaces'. The 8.3 short path has no spaces and
    # sidesteps the bug; fall back to the normal resolved path everywhere
    # else, or if short-path generation is unavailable/disabled.
    resolved = str(Path(path).resolve())
    if platform.system() == 'Windows' and ' ' in resolved:
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(260)
            if ctypes.windll.kernel32.GetShortPathNameW(resolved, buf, 260):
                return buf.value
        except Exception:
            pass
    return resolved

def ssh_args(target, command):
    # Host aliases must be organizer-controlled, never supplied by an API caller.
    alias=target['alias']
    if not alias.replace('-','').replace('_','').isalnum():
        raise ValueError('Invalid SSH alias')
    return ['ssh','-F',config_path(target['config']),'-T',
            '-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
            '-o','ConnectTimeout=8','-o','ServerAliveInterval=5',
            '-o','ServerAliveCountMax=2',alias,command]

def execute(target, command):
    if not isinstance(command,str) or not command.strip() or len(command)>8192 or '\x00' in command:
        raise ValueError('Command must contain 1 to 8192 characters')
    # Disk-backed capture prevents unbounded RAM consumption from remote output.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        p=subprocess.Popen(ssh_args(target,command),stdout=out,stderr=err,stdin=subprocess.DEVNULL)
        deadline=time.monotonic()+30; reason=None
        while p.poll() is None:
            if time.monotonic()>deadline: reason='timeout'
            if os.fstat(out.fileno()).st_size+os.fstat(err.fileno()).st_size>1048576: reason='output_limit'
            if reason: p.kill(); break
            time.sleep(.05)
        p.wait(); out.seek(0); err.seek(0)
        return {'exit_code':p.returncode,'termination':reason,
                'stdout':out.read(65536).decode('utf-8','replace'),
                'stderr':err.read(65536).decode('utf-8','replace'),
                'truncated':os.fstat(out.fileno()).st_size>65536 or os.fstat(err.fileno()).st_size>65536}

def handler(config, token):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_POST(self):
            self.connection.settimeout(10)
            supplied=self.headers.get('Authorization','')
            if not hmac.compare_digest(supplied,'Bearer '+token):
                return self.reply(401,{'error':'Unauthorized'})
            try:
                n=int(self.headers.get('Content-Length','0'))
                if not 0<n<=16384: raise ValueError('Invalid body length')
                data=json.loads(self.rfile.read(n))
                if not isinstance(data,dict): raise ValueError('Expected JSON object')
                ledger=Ledger(config['db'])
                try:
                    ledger.active(config['round'])
                    if self.path=='/execute':
                        target=data['target']
                        if target not in config['targets']: return self.reply(403,{'error':'Target not permitted'})
                        result=execute(config['targets'][target],data['command'])
                        # Evidence remains private: it can include captured flags and credentials.
                        with open(config['audit'],'a',encoding='utf-8') as f:
                            f.write(json.dumps({'at':time.time(),'round':config['round'],'role':config['role'],
                                'target':target,'command':data['command'],'result':result})+'\n')
                    elif self.path=='/submit' and config['role']=='red':
                        result=ledger.submit(config['round'],data['objective'],data['token'])
                    elif self.path=='/score': result=ledger.report(config['round'])
                    else: return self.reply(404,{'error':'Unknown endpoint'})
                finally: ledger.db.close()
                self.reply(200,result)
            except (ValueError,KeyError,TypeError): self.reply(400,{'error':'Invalid request or inactive round'})
            except Exception: self.reply(503,{'error':'Operation failed; check organizer configuration'})
        def reply(self,status,data):
            body=json.dumps(data).encode(); self.send_response(status)
            self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(body)))
            self.end_headers(); self.wfile.write(body)
    return Handler

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('config'); a=p.parse_args()
    c=json.loads(Path(a.config).read_text())
    if c['role'] not in ('red','blue'): raise ValueError('Invalid role')
    if c['role']=='red' and set(c['targets'])!={'kali'}: raise ValueError('Red bridge may only target Kali')
    token=os.environ[c['token_env']]
    if len(token)<32: raise ValueError('Use a random API token of at least 32 characters')
    Path(c['audit']).parent.mkdir(parents=True,exist_ok=True)
    server=HTTPServer(('127.0.0.1',c['port']),handler(c,token))
    print(f"{c['role']} bridge listening on 127.0.0.1:{c['port']}",flush=True)
    server.serve_forever()

if __name__=='__main__': main()

