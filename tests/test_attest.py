import pathlib, sys, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "engagement-tool"))
from attest import judge

def att(status): return {"connectivity": {"ssh": {"reachable": True}}, "objectives": {"ssh": {"status": status}}}
def dfn(**kw):
    r = {"objective": "ssh", "claimed": True, "state_ok": True, "legit_ok": True}; r.update(kw)
    return {"results": [r]}

class T(unittest.TestCase):
    def stages(self, *a, **kw): return judge("ssh", *a, **kw)[0]
    def test_fixed_and_confirmed_is_block_plus_remediate(self):
        self.assertEqual(self.stages(att("open"), att("closed"), dfn(), None), ["block", "remediate"])
    def test_fixed_but_not_probeable_is_remediate_only(self):
        self.assertEqual(self.stages(att("open"), att("not_probeable"), dfn(), None), ["remediate"])
    def test_containment_only_is_block(self):
        self.assertEqual(self.stages(att("open"), att("closed"), dfn(state_ok=False), None), ["block"])
    def test_still_open(self): self.assertEqual(self.stages(att("open"), att("open"), dfn(), None), [])
    def test_undocumented_fix(self): self.assertEqual(self.stages(att("open"), att("closed"), dfn(claimed=False), None), [])
    def test_lying_defender(self): self.assertEqual(self.stages(att("open"), att("closed"), dfn(state_ok=False, claimed=False), None), [])
    def test_service_broken(self): self.assertEqual(self.stages(att("open"), att("closed"), dfn(legit_ok=False), None), [])
    def test_never_vulnerable(self): self.assertEqual(self.stages(att("closed"), att("closed"), dfn(), None), [])
    def test_no_baseline_strict(self): self.assertEqual(self.stages(None, att("closed"), dfn(), None), [])
    def test_assumed_baseline(self):
        self.assertEqual(self.stages(None, att("closed"), dfn(), None, assume_baseline=True), ["block", "remediate"])
    def test_host_down(self):
        post = att("closed"); post["connectivity"]["ssh"]["reachable"] = False
        self.assertEqual(self.stages(att("open"), post, dfn(), None), [])
    def test_no_claim(self): self.assertEqual(judge("ssh", att("open"), att("closed"), {"results": []}, None)[0], [])

if __name__ == "__main__": unittest.main()
