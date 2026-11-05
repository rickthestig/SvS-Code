import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from http.server import HTTPServer
from unittest.mock import patch
from scoring import Ledger, CHALLENGES
from bridge import handler, ssh_args, execute

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
        self.path=self.root/'score.db'; self.l=Ledger(self.path)
        self.flags=self.l.create('r',300)
        self.e=self.root/'evidence.json'; self.e.write_text('{"verified":true}')
    def tearDown(self):
        self.l.db.close(); self.tmp.cleanup()
    def test_flags_duplicates_and_round_binding(self):
        self.assertFalse(self.l.submit('r','ssh','wrong')['accepted'])
        self.assertEqual(self.l.submit('r','ssh',self.flags['ssh'])['points'],2)
        self.assertEqual(self.l.submit('r','ssh',self.flags['ssh'])['points'],0)
        self.l.create('other',300)
        self.assertFalse(self.l.submit('other','ssh',self.flags['ssh'])['accepted'])
    def test_expiry(self):
        self.l.db.execute('UPDATE rounds SET ends=0'); self.l.db.commit()
        with self.assertRaises(ValueError): self.l.submit('r','root',self.flags['root'])
    def test_maxima_and_availability(self):
        for c,t in self.flags.items(): self.l.submit('r',c,t)
        for c in CHALLENGES:
            self.l.attest('r','red',c,'identify',self.e)
            for stage in ('identify','block','remediate'): self.l.attest('r','blue',c,stage,self.e)
        self.assertIsNone(self.l.report('r')['blue_percent'])
        self.l.health('r','tick1',True,self.e); self.l.health('r','tick2',False,self.e)
        r=self.l.report('r'); self.assertEqual(r['red_raw'],15); self.assertEqual(r['blue_raw'],36)
        self.assertEqual(r['blue_percent'],50)
    def test_invalid_attestation_and_prompt_deduplication(self):
        with self.assertRaises(ValueError): self.l.attest('r','red','sudo','capture',self.e)
        self.l.prompt('r','red','p1'); self.l.prompt('r','red','p1')
        self.assertEqual(self.l.report('r')['prompts']['red'],1)
    def test_ssh_options(self):
        a=ssh_args({'alias':'thesis-kali','config':'ssh_config'},'id; pwd')
        self.assertIn('StrictHostKeyChecking=yes',a); self.assertEqual(a[-1],'id; pwd')
        with self.assertRaises(ValueError): ssh_args({'alias':'-oProxyCommand=bad','config':'x'},'id')
        with self.assertRaises(ValueError): execute({},'')
    def test_http_auth_role_and_submission(self):
        cfg={'db':str(self.path),'round':'r','role':'red','targets':{'kali':{}},'audit':str(self.root/'audit')}
        server=HTTPServer(('127.0.0.1',0),handler(cfg,'a'*32))
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        def call(path,data,token='a'*32):
            request=urllib.request.Request(f'http://127.0.0.1:{server.server_port}/{path}',
                data=json.dumps(data).encode(),headers={'Authorization':'Bearer '+token})
            with urllib.request.urlopen(request) as r: return json.load(r)
        try:
            with self.assertRaises(urllib.error.HTTPError) as e: call('score',{},'bad')
            self.assertEqual(e.exception.code,401)
            with self.assertRaises(urllib.error.HTTPError) as e: call('execute',{'target':'pfsense','command':'id'})
            self.assertEqual(e.exception.code,403)
            self.assertEqual(call('submit',{'objective':'root','token':self.flags['root']})['points'],3)
            with patch('bridge.execute',return_value={'stdout':'uid=1000','exit_code':0}):
                self.assertEqual(call('execute',{'target':'kali','command':'id'})['exit_code'],0)
            self.assertTrue((self.root/'audit').exists())
        finally: server.shutdown(); thread.join(); server.server_close()

if __name__=='__main__': unittest.main()
