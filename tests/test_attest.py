import pathlib, sys, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "engagement-tool"))
from attest import judge

def att(status): return {"connectivity": {"ssh": {"reachable": True}}, "objectives": {"ssh": {"status": status}}}
def dfn(**kw):
    r = {"objective": "ssh", "claimed_stage": "remediate", "verified": True, "state_ok": True, "legit_ok": True}; r.update(kw)
    return {"results": [r]}

class T(unittest.TestCase):
    def test_remediate(self): self.assertEqual(judge("ssh", att("open"), att("closed"), dfn(), None)[0], "remediate")
    def test_block_only(self): self.assertEqual(judge("ssh", att("open"), att("closed"), dfn(claimed_stage="block"), None)[0], "block")
    def test_still_open(self): self.assertIsNone(judge("ssh", att("open"), att("open"), dfn(), None)[0])
    def test_lying_defender(self): self.assertIsNone(judge("ssh", att("open"), att("closed"), dfn(verified=False, state_ok=False), None)[0])
    def test_service_broken(self): self.assertIsNone(judge("ssh", att("open"), att("closed"), dfn(verified=False, legit_ok=False), None)[0])
    def test_never_vulnerable(self): self.assertIsNone(judge("ssh", att("closed"), att("closed"), dfn(), None)[0])
    def test_no_baseline_strict(self): self.assertIsNone(judge("ssh", None, att("closed"), dfn(), None)[0])
    def test_assumed_baseline(self): self.assertEqual(judge("ssh", None, att("closed"), dfn(), None, assume_baseline=True)[0], "remediate")
    def test_host_down(self):
        post = att("closed"); post["connectivity"]["ssh"]["reachable"] = False
        self.assertIsNone(judge("ssh", att("open"), post, dfn(), None)[0])
    def test_no_claim(self): self.assertIsNone(judge("ssh", att("open"), att("closed"), {"results": []}, None)[0])
if __name__ == "__main__": unittest.main()
