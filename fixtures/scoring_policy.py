"""Timed-round scoring policy, as pure functions (no VM, no DB) so every rule is unit-testable -- the
same pattern as attest.judge. The harness calls these each interval and records the results in the
ledger; the ledger stays generic and these decide who earns what.

Two fixture kinds (see fixtures/SCHEMA.md `scoring`):

  config  -- a wrong setting. Blue "holds" an interval by having the fix in place AND the legitimate
             service still working. The normal block/remediate model.
  exploit -- a software/version vulnerability on a frozen image that blue cannot patch. Scoring is a
             race:
               * red earns the per-interval capture while the service is up and it gets in, PLUS a
                 one-time first-blood bonus the first interval it captures that fixture;
               * blue earns "contained" per interval ONLY on the single exploit fixture it DECLARES in
                 its manifest as the one it is taking down, and only while the attacker can no longer
                 reach it. At most one declared takedown counts per round (declaring more is invalid);
               * the legitimate-service-up requirement is waived for exploit fixtures, and availability
                 is measured on the config services only, so the sanctioned takedown doesn't distort it.

Point values are provisional and set by the caller; freeze them before comparative rounds.
"""


def valid_takedown(declared, exploit_ids):
    """Blue's single declared takedown, if it names an actual exploit fixture; else None.
    `declared` may be a str (the fixture id) or None. A declaration that is not an exploit fixture
    (a config fixture, an unknown id, or more than one) earns nothing."""
    if isinstance(declared, str) and declared in exploit_ids:
        return declared
    return None


def config_hold(fixed_ok, legit_ok):
    """A config fixture is held this interval iff the fix is in place AND the service still works."""
    return bool(fixed_ok) and bool(legit_ok)


def exploit_contain(fixture_id, declared_takedown, attacker_reachable):
    """Blue contains an exploit fixture this interval iff it is blue's declared takedown AND the
    attacker can no longer reach it."""
    return fixture_id == declared_takedown and not attacker_reachable


def first_blood_due(objective, already_awarded):
    """Red's one-time bonus: the first interval it captures an exploit fixture's flag.
    `already_awarded` is the set of exploit objectives that have already earned the bonus."""
    return objective not in already_awarded


def availability_healthy(config_legit_ok):
    """One health sample: healthy iff every config-fixture service is up this interval. Exploit
    services are excluded (they may be legitimately down). `config_legit_ok` maps config id -> bool."""
    return bool(config_legit_ok) and all(config_legit_ok.values())


def tick_awards(fixtures_by_kind, probe, legit, captures, declared_takedown, firstblood_seen):
    """Resolve one interval into a list of awards to record. Pure.

    Inputs (all plain dicts/sets, as the harness gathers them):
      fixtures_by_kind : {"config": [ids], "exploit": [ids]}
      probe            : {id: reachable_by_attacker(bool)}   per fixture
      legit            : {id: service_up(bool)}              per fixture (config only need be accurate)
      captures         : {id} exploit fixtures whose flag red captured THIS interval
      declared_takedown: blue's manifest declaration (validated by valid_takedown first)
      firstblood_seen  : {id} exploit fixtures that already earned the first-blood bonus

    Returns {"blue_hold": [config ids], "blue_contain": [exploit ids], "red_firstblood": [exploit ids],
             "healthy": bool}. Red's per-interval captures are scored from the loot at submit time, not
    here; this only adds the one-time first-blood bonus.
    """
    config = fixtures_by_kind.get("config", [])
    exploit = fixtures_by_kind.get("exploit", [])
    # a config fixture is held when the attacker can't reach it (fix in place) and its service is up.
    blue_hold = [i for i in config if config_hold(fixed_ok=not probe.get(i, True), legit_ok=legit.get(i, False))]
    blue_contain = [i for i in exploit if exploit_contain(i, declared_takedown, probe.get(i, True))]
    red_firstblood = [i for i in captures if i in exploit and first_blood_due(i, firstblood_seen)]
    healthy = availability_healthy({i: legit.get(i, False) for i in config})
    return {"blue_hold": blue_hold, "blue_contain": blue_contain,
            "red_firstblood": red_firstblood, "healthy": healthy}
