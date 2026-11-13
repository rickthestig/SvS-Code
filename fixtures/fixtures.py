"""Load a fixture set (fixtures/SCHEMA.md) and derive objectives, maxima, flag locations and the
per-objective check plan from it, so a cohort is defined in one JSON file instead of being spread
across scoring.py / install_flags.py / verification_plan.json.

This module is pure data handling: it reads the list and reshapes it. It contains no vulnerable
configuration and no exploit logic -- the weaknesses live on the target image, and the check handlers
live in defender_verify.py / attacker_verify.py. Stdlib only."""
import json
from pathlib import Path

FAMILIES = ("http", "ftp", "smb", "ssh", "mysql", "irc", "privesc", "lateral")
STAGES_RED = ("capture",)
STAGES_BLUE = ("block", "remediate")
TICK_POINTS = 1  # provisional per-interval weight; freeze before comparative runs


class FixtureSet:
    def __init__(self, data: dict):
        self.cohort = data["cohort"]
        self.image = data.get("image", {})
        self.hosts = data["hosts"]
        self.fixtures = data["fixtures"]
        self._validate()

    @classmethod
    def load(cls, path) -> "FixtureSet":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def _validate(self) -> None:
        seen = set()
        for f in self.fixtures:
            fid = f["id"]
            if fid in seen:
                raise ValueError(f"duplicate fixture id: {fid}")
            seen.add(fid)
            if f["family"] not in FAMILIES:
                raise ValueError(f"{fid}: unknown family {f['family']!r} (one of {FAMILIES})")
            if f["host"] not in self.hosts:
                raise ValueError(f"{fid}: host {f['host']!r} not in hosts")
            if f.get("scoring", "config") not in ("config", "exploit"):
                raise ValueError(f"{fid}: scoring must be 'config' or 'exploit'")
            pts = f.get("points", {})
            if "flag" in f and "capture" not in pts:
                raise ValueError(f"{fid}: has a flag but no 'capture' points")
            if "flag" not in f and "capture" in pts:
                raise ValueError(f"{fid}: 'capture' points but no flag to capture")

    # ---- derived views ------------------------------------------------------
    @property
    def ids(self) -> list:
        return [f["id"] for f in self.fixtures]

    @property
    def flag_ids(self) -> list:
        return [f["id"] for f in self.fixtures if "flag" in f]

    @property
    def config_ids(self) -> list:
        return [f["id"] for f in self.fixtures if f.get("scoring", "config") == "config"]

    @property
    def exploit_ids(self) -> list:
        return [f["id"] for f in self.fixtures if f.get("scoring", "config") == "exploit"]

    def by_id(self, fid: str) -> dict:
        return next(f for f in self.fixtures if f["id"] == fid)

    def families(self) -> dict:
        out = {}
        for f in self.fixtures:
            out.setdefault(f["family"], []).append(f["id"])
        return out

    def maxima(self) -> dict:
        # red: flag captures + red identify; blue: block + remediate + blue identify.
        red = sum(f["points"].get("capture", 0) for f in self.fixtures if "flag" in f)
        red += sum(f["points"].get("identify", 0) for f in self.fixtures if f.get("check"))
        blue = sum(f["points"].get("block", 0) + f["points"].get("remediate", 0)
                   + f["points"].get("identify", 0) for f in self.fixtures)
        return {
            "red_max": red,
            "blue_max": blue,
            "tick_red_max_per_tick": len(self.flag_ids) * TICK_POINTS,
            "tick_blue_max_per_tick": len(self.fixtures) * TICK_POINTS,
        }

    def flag_locations(self) -> dict:
        """{id: {path, owner, mode, host, ip}} for the installer."""
        out = {}
        for f in self.fixtures:
            if "flag" in f:
                fl = f["flag"]
                out[f["id"]] = {"path": fl["path"], "owner": fl.get("owner", "root"),
                                "mode": fl.get("mode", "0444"), "host": f["host"],
                                "ip": self.hosts[f["host"]]["ip"]}
        return out

    def verification_plan(self, host: str | None = None) -> dict:
        """The operator-only per-objective plan (shape defender_verify.py already consumes)."""
        objs = {}
        for f in self.fixtures:
            if host and f["host"] != host:
                continue
            if "check" not in f:   # capture-only fixture (e.g. root); nothing to attest
                continue
            objs[f["id"]] = {"statement": f.get("statement", f["id"]),
                             "check": f["check"], "legit": f["legit"],
                             "keywords": f.get("keywords", [f["id"]])}
        return {"_note": "Generated from a fixture set; operator-only, never shown to the defender.",
                "objectives": objs}


if __name__ == "__main__":
    import sys
    fs = FixtureSet.load(sys.argv[1] if len(sys.argv) > 1
                         else Path(__file__).parent / "legacy-weak.json")
    print(f"cohort: {fs.cohort}  ({len(fs.fixtures)} fixtures)")
    print("families:", {k: len(v) for k, v in fs.families().items()})
    print("maxima:", fs.maxima())
