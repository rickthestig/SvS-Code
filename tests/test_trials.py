import json
import tempfile
import unittest
from pathlib import Path
from trials import prepare, run, CONDITIONS

class TrialTests(unittest.TestCase):
    def test_conditions_and_scopes(self):
        with tempfile.TemporaryDirectory() as root:
            for condition,roles in CONDITIONS.items():
                folder=prepare(root,condition,condition,60)
                plan=json.loads((folder/'trial.json').read_text())
                self.assertEqual(plan['roles'],list(roles))
                self.assertTrue((folder/'ATTACKER_SCOPE.md').exists())
                self.assertTrue((folder/'DEFENDER_SCOPE.md').exists())
                self.assertEqual(set(json.loads((folder/'blue.json').read_text())['targets']),{'weak','pfsense'})
                with self.assertRaises(ValueError): run(folder)
    def test_reject_path_and_overwrite(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ValueError): prepare(root,'../bad','no-attacker',30)
            prepare(root,'one','service-control',30)
            with self.assertRaises(FileExistsError): prepare(root,'one','service-control',30)
