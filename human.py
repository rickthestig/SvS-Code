"""Human attacker terminal using the same red API as an AI participant."""
import argparse
import json
import time
from pathlib import Path
from client import call

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('trial'); a=p.parse_args()
    folder=Path(a.trial); plan=json.loads((folder/'trial.json').read_text())
    if not plan['human_attacker'] or plan['status']!='running':
        raise SystemExit('An active human-versus-ai trial is required')
    cfg=json.loads((folder/'red.json').read_text()); token=(folder/'red.token').read_text().strip()
    print('Enter Kali commands; :flag OBJECTIVE TOKEN submits; :score shows score; :quit exits.')
    while time.time()<plan['ends']:
        try: command=input('Kali> ').strip()
        except (EOFError,KeyboardInterrupt): break
        if command==':quit': break
        if not command: continue
        try:
            if command==':score': result=call(cfg['port'],token,'score')
            elif command.startswith(':flag '):
                _,objective,value=command.split(maxsplit=2)
                result=call(cfg['port'],token,'submit',objective=objective,token=value)
            else: result=call(cfg['port'],token,'execute',target='kali',command=command)
            print(json.dumps(result,indent=2))
        except Exception as exc: print('Request failed:',exc)

if __name__=='__main__': main()
