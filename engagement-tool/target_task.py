from lab import *
import sys
def target_connect(vm, ip, user='labadmin', password=None):
 channel=vm.get_transport().open_channel('direct-tcpip',(ip,22),('127.0.0.1',0),timeout=10)
 client=paramiko.SSHClient();hosts=WORK/'target-known-hosts'
 if hosts.exists():client.load_host_keys(str(hosts))
 client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
 client.connect(ip,username=user,password=password,key_filename=str(WORK/'lab-admin-key') if password is None else None,sock=channel,look_for_keys=False,allow_agent=False,timeout=10)
 client.save_host_keys(str(hosts));return client
if __name__=='__main__':
 vm=connect()
 try:
  t=target_connect(vm,sys.argv[1])
  try:print(run(t,sys.argv[2],timeout=180))
  finally:t.close()
 finally:vm.close()
