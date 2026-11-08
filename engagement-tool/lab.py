import sys, pathlib, configparser, base64, hashlib, json
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, str(pathlib.Path(__file__).parent/'pydeps'))
import paramiko, requests
WORK=pathlib.Path(__file__).parent
PROJECT='47184b19-f33d-4e64-bb7b-239f28108e69'
class Pinned(paramiko.MissingHostKeyPolicy):
 def missing_host_key(self, client, hostname, key):
  fp=base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
  if fp!='UOBvO3ouz55SxfsTlf4OS5dmmEHqn0cb4btKdnh4Ups': raise RuntimeError('GNS3 host key changed')
def connect():
 c=paramiko.SSHClient();c.set_missing_host_key_policy(Pinned())
 c.connect('192.168.122.128',username='gns3',password='gns3',look_for_keys=False,allow_agent=False,timeout=10)
 return c
def run(c, cmd, timeout=60):
 _,o,e=c.exec_command(cmd,timeout=timeout); out=o.read().decode();err=e.read().decode();rc=o.channel.recv_exit_status()
 if rc: raise RuntimeError(f'Exit {rc}: {err}\n{out}')
 return out
def upload(c, local, remote):
 with c.open_sftp() as s:s.put(str(local),remote)
def api(method,path,body=None):
 cfg=configparser.ConfigParser();cfg.read(pathlib.Path.home()/'AppData/Roaming/GNS3/2.2/gns3_server.ini')
 sec=cfg['Server'];r=requests.request(method,'http://localhost:3080/v2/'+path,auth=(sec['user'],sec['password']),json=body,timeout=60);r.raise_for_status()
 return r.json() if r.content else None
if __name__=='__main__':
 c=connect()
 try:print(run(c,sys.argv[1]))
 finally:c.close()
