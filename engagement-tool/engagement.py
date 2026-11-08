#!/usr/bin/env python3
"""
One command to run the red-vs-blue lab engagement end to end, instead of the ~20 hand-run steps
(reset targets, reinstall flags, sweep Kali, upload scope docs, verify, launch both agents,
poll status, pull results, submit flags, archive) that this engagement has needed up to now.

    python engagement.py start              # full reset + kickoff, both agents launched together
    python engagement.py start --reuse-round --skip-target-reset   # relaunch without re-provisioning
    python engagement.py status             # one-shot status
    python engagement.py status --watch     # live dashboard, refreshes until both agents finish
    python engagement.py collect            # pull results, submit flags, run auto-attest, archive
    python engagement.py stop               # stop both agents (e.g. to abort and redo)
    python engagement.py check              # verify everything's reachable before committing to `start`

Every subcommand after `start` reads what it needs from .engagement_state.json next to this
script -- you don't need to remember or pass round names or session IDs between invocations.
"""
import argparse
import datetime
import json
import pathlib
import shutil
import subprocess
import sys
import tarfile
import time

import engagement_common as ec


def cmd_start(args) -> None:
    round_name = args.round or ec.next_round_name()
    print(f"=== Starting engagement: round {round_name} ===")

    if not args.skip_target_reset:
        print("-- resetting targets to clean baseline --")
        ec.reset_targets()
        print("-- installing flags --")
        ec.install_flags(round_name, reuse_bundle=args.reuse_round)
    else:
        print("-- skipping target reset/flag install (--skip-target-reset) --")
        # Still take them down/up cleanly so there's no reset-script noise in defender's logs
        # and blue access is confirmed fresh, even when reusing already-provisioned disks.
        for name, (node_id, ip) in ec.NODES.items():
            if ec.node_status(node_id) == "started":
                ec.clean_shutdown(ip, node_id)

    print("-- resetting attacker harness (loot/logs/scans/scope, shell history, known_hosts) --")
    ec.reset_harness()

    print("-- uploading scope docs for this round --")
    ec.upload_scope_docs(round_name)

    print("-- powering targets on, restoring blue access --")
    for name, (node_id, ip) in ec.NODES.items():
        if ec.node_status(node_id) != "started":
            ec.start_node(node_id)
    ec.reset_targets(list(ec.NODES), restore_only=True)

    if not ec.verify_scope_present():
        print("ERROR: scope doc is not present/non-empty on the harness after upload -- not launching.",
              file=sys.stderr)
        sys.exit(1)
    print("-- scope doc verified present --")

    print(f"-- launching attacker (model={args.model}) --")
    session_id = ec.launch_attacker(model=args.model)
    print(f"   attacker session: {session_id}")

    print("-- launching defender --")
    proc = ec.launch_defender()
    time.sleep(3)
    transcript = ec.latest_defender_transcript()
    print(f"   defender pid: {proc.pid}, transcript: {transcript.name if transcript else '(not yet created)'}")

    ec.save_state(
        round=round_name,
        attacker_session=session_id,
        defender_pid=proc.pid,
        defender_transcript=str(transcript) if transcript else None,
        started_at=datetime.datetime.now().isoformat(timespec="seconds"),
        model=args.model,
    )
    ec.log_event(
        f"engagement.py start: round `{round_name}`, attacker session `{session_id}` "
        f"(model {args.model}), defender pid {proc.pid}."
    )
    print(f"=== Both agents running. `python engagement.py status --watch` to follow along. ===")


def _attacker_line(state: dict) -> str:
    session_id = state.get("attacker_session")
    if not session_id:
        return "attacker: (no session recorded)"
    info = ec.attacker_session_status(session_id)
    if info is None:
        return f"attacker: session {session_id} not found (exited or stopped)"
    return f"attacker: session {session_id} — status={info.get('status')} state={info.get('state')}"


def _defender_line(state: dict) -> tuple[str, bool]:
    pid = state.get("defender_pid")
    alive = False
    if pid:
        try:
            import psutil  # type: ignore
            alive = psutil.pid_exists(pid)
        except ImportError:
            # No psutil dependency wanted for this -- fall back to a Windows-native check.
            r = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True)
            alive = str(pid) in r.stdout
    transcript = ec.latest_defender_transcript()
    label = f"defender: pid={pid} alive={alive}"
    if transcript:
        label += f" transcript={transcript.name}"
        try:
            tail = transcript.read_text(encoding="utf-8", errors="replace").splitlines()[-1]
            label += f"\n  last line: {tail[:160]}"
        except Exception:  # noqa: BLE001
            pass
    return label, alive


def cmd_status(args) -> None:
    state = ec.load_state()
    if not state:
        print("No engagement state found -- has `engagement.py start` been run?")
        return

    def snapshot():
        print(f"--- round {state.get('round')} (started {state.get('started_at')}) "
              f"[{datetime.datetime.now().strftime('%H:%M:%S')}] ---")
        print(_attacker_line(state))
        d_line, _ = _defender_line(state)
        print(d_line)

    if not args.watch:
        snapshot()
        return

    print(f"Watching every {args.interval}s — Ctrl+C to stop watching (agents keep running).")
    try:
        while True:
            snapshot()
            attacker_info = ec.attacker_session_status(state.get("attacker_session", ""))
            attacker_done = attacker_info is None or attacker_info.get("state") == "done"
            _, defender_alive = _defender_line(state)
            if attacker_done and not defender_alive:
                print("\nBoth agents finished.")
                break
            print()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n(stopped watching; agents are still running)")


def cmd_stop(args) -> None:
    """Stops both agents. Does not reset the harness/targets or clear state -- `start` handles
    provisioning for the next run regardless of whether it's following a normal finish or an
    abort, so there's no cleanup to duplicate here."""
    state = ec.load_state()
    if not state:
        print("No engagement state found -- nothing to stop.")
        return
    session_id = state.get("attacker_session")
    if session_id:
        client = ec.kali_ssh()
        try:
            rc, out, err = ec.run(client, f"claude stop {session_id}")
            print(out.strip() or err.strip())
        finally:
            client.close()
    pid = state.get("defender_pid")
    if pid:
        try:
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
            print(f"defender pid {pid} stopped")
        except Exception as e:  # noqa: BLE001
            print(f"could not stop defender pid {pid}: {e}")
    ec.log_event(f"engagement.py stop: round `{state.get('round')}` stopped by operator.")
    # Not a reset -- `start` already resets everything itself (targets, harness, scope docs)
    # every time it runs, regardless of what state it finds, so there's nothing here to
    # duplicate. This just clears the dead session/PID out of state so a `status` run between
    # now and the next `start` doesn't show stale info.
    ec.STATE_FILE.unlink(missing_ok=True)
    print("state cleared")


def cmd_collect(args) -> None:
    state = ec.load_state()
    if not state:
        print("No engagement state found.")
        sys.exit(1)
    round_name = state["round"]
    archive_name = args.archive_name or f"run-results-{datetime.date.today():%Y%m%d}-{round_name}"
    dest = ec.TEST_RUN_DIR / archive_name
    dest.mkdir(parents=True, exist_ok=True)
    print(f"=== Collecting results for {round_name} into {dest} ===")

    print("-- pulling attacker logs/loot/scans from Kali --")
    client = ec.kali_ssh()
    try:
        ec.run(client, "cd ~/harness && tar czf /tmp/loot.tar.gz loot && tar czf /tmp/scans.tar.gz scans")
        sftp = client.open_sftp()
        for remote, local in [
            ("/home/kali/harness/logs/running-log.md", dest / "attacker-running-log.md"),
            ("/home/kali/harness/logs/final-report.md", dest / "attacker-final-report.md"),
            ("/tmp/loot.tar.gz", dest / "attacker-loot.tar.gz"),
            ("/tmp/scans.tar.gz", dest / "attacker-scans.tar.gz"),
        ]:
            try:
                sftp.get(remote, str(local))
            except FileNotFoundError:
                print(f"   (not found on Kali: {remote} -- skipping)")
        sftp.close()
    finally:
        client.close()

    print("-- copying scope docs, engagement log, scripts, defender transcript --")
    for f in [ec.AGENT_SCOPE_DOC, ec.DEFENDER_SCOPE_DOC, ec.ENGAGEMENT_LOG,
              ec.TEST_RUN_DIR / "SUPPLEMENTARY_SCORING.md", ec.DEFENDER_SCRIPT,
              ec.WORK / "auto_attest.py"]:
        if f.is_file():
            shutil.copy2(f, dest / f.name)
    transcript = state.get("defender_transcript")
    if transcript and pathlib.Path(transcript).is_file():
        shutil.copy2(transcript, dest / pathlib.Path(transcript).name)

    print("-- parsing captured flags and submitting to the scoring ledger --")
    flags_file = dest / "attacker-loot.tar.gz"
    submitted = []
    if flags_file.is_file():
        with tarfile.open(flags_file) as tf:
            try:
                member = tf.getmember("loot/flags.md")
                flags_text = tf.extractfile(member).read().decode(errors="replace")
            except KeyError:
                flags_text = ""
        import re
        for m in re.finditer(
            r"\|\s*(\w+)\s*\|\s*(FLAG\{[^}]*\})\s*\|", flags_text
        ):
            objective, token = m.group(1), m.group(2)
            r = subprocess.run(
                [sys.executable, "scoring.py", "submit", round_name, objective, token],
                cwd=ec.LAB_KIT_DIR, capture_output=True, text=True,
            )
            print(f"   submit {objective}: {r.stdout.strip() or r.stderr.strip()}")
            submitted.append(objective)

    print("-- checking for automatable blue 'block' credit (auto_attest.py) --")
    report_path = dest / "attacker-final-report.md"
    db_path = ec.LAB_KIT_DIR / "private" / "score.db"
    if report_path.is_file():
        for objective in ("ssh", "smb", "web", "cron", "setuid", "sudo"):
            r = subprocess.run(
                [sys.executable, "auto_attest.py", round_name, objective,
                 "--attacker-report", str(report_path), "--db", str(db_path), "--yes"],
                cwd=ec.WORK, capture_output=True, text=True,
            )
            out = (r.stdout or r.stderr).strip().splitlines()
            print(f"   {objective}: {out[-1] if out else '(no output)'}")

    print("-- snapshotting scoring standing + ledger --")
    r = subprocess.run([sys.executable, "scoring.py", "report", round_name],
                        cwd=ec.LAB_KIT_DIR, capture_output=True, text=True)
    (dest / "scoring-final-standing.json").write_text(r.stdout)
    print(r.stdout)
    ledger_dest = dest / "scoring-ledger-private"
    ledger_dest.mkdir(exist_ok=True)
    if db_path.is_file():
        shutil.copy2(db_path, ledger_dest / "score.db")
    bundle = ec.LAB_KIT_DIR / "private" / f"{round_name}-flags.json"
    if bundle.is_file():
        shutil.copy2(bundle, ledger_dest / bundle.name)

    ec.log_event(f"engagement.py collect: round `{round_name}` archived to `{dest.name}`; "
                 f"submitted flags: {submitted or 'none'}.")
    print(f"=== Done. Archive: {dest} ===")


def cmd_check(args) -> None:
    """Fail fast with a clear diagnosis instead of `start` hanging or half-completing partway
    through a multi-minute run because something basic (GNS3 VM down, Mistral key missing) was
    wrong from the start."""
    ok = True

    def report(label: str, passed: bool, detail: str = "") -> None:
        nonlocal ok
        ok = ok and passed
        mark = "OK" if passed else "FAIL"
        print(f"[{mark}] {label}" + (f" — {detail}" if detail else ""))

    try:
        vm = ec.connect()
        vm.close()
        report("GNS3 VM reachable", True)
    except Exception as e:  # noqa: BLE001
        report("GNS3 VM reachable", False, str(e))

    try:
        client = ec.kali_ssh()
        client.close()
        report("Kali reachable (via GNS3 VM pivot)", True)
    except Exception as e:  # noqa: BLE001
        report("Kali reachable (via GNS3 VM pivot)", False, str(e))

    for name, (node_id, ip) in ec.NODES.items():
        try:
            status = ec.node_status(node_id)
            report(f"target '{name}' node queryable", True, f"status={status}")
        except Exception as e:  # noqa: BLE001
            report(f"target '{name}' node queryable", False, str(e))

    report("Defender API key present (defender.txt)",
           ec.DEFENDER_KEY_FILE.is_file() and ec.DEFENDER_KEY_FILE.stat().st_size > 0,
           str(ec.DEFENDER_KEY_FILE))
    # Attacker key is optional today -- launch_attacker() falls back to Kali's existing `claude`
    # auth state if attacker.txt isn't there, so its absence doesn't fail the check.
    if ec.ATTACKER_KEY_FILE.is_file() and ec.ATTACKER_KEY_FILE.stat().st_size > 0:
        print(f"[OK] Attacker API key present (attacker.txt) — {ec.ATTACKER_KEY_FILE}")
    else:
        print(f"[INFO] No attacker.txt — attacker will use Kali's existing `claude` auth state "
              f"instead of an API key. Create {ec.ATTACKER_KEY_FILE} for the full run.")

    for label, path in [
        ("defender_agent.py", ec.DEFENDER_SCRIPT),
        ("scoring.py", ec.LAB_KIT_DIR / "scoring.py"),
        ("install_flags.py", ec.LAB_KIT_DIR / "install_flags.py"),
        ("AGENT_PENTEST_SCOPE.md", ec.AGENT_SCOPE_DOC),
        ("DEFENDER_SCOPE.md", ec.DEFENDER_SCOPE_DOC),
        ("thesis_blue SSH key", pathlib.Path(ec.THESIS_BLUE_KEY)),
    ]:
        report(f"{label} present", path.is_file(), str(path))

    print()
    print("All checks passed — ready for `engagement.py start`." if ok
          else "Some checks failed — fix those before running `start`.")
    sys.exit(0 if ok else 1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_start = sub.add_parser("start", help="Full reset and kickoff; launches both agents together.")
    p_start.add_argument("--round", help="Round name (default: auto-increment agent-pentest-NNN).")
    p_start.add_argument("--reuse-round", action="store_true",
                          help="Reuse an existing round's flag bundle instead of creating a new round.")
    p_start.add_argument("--skip-target-reset", action="store_true",
                          help="Don't disk-reset targets or reinstall flags (for a quick relaunch); "
                               "still power-cycles them cleanly before launch.")
    p_start.add_argument("--model", default="opus", help="Attacker's Claude Code model alias (default: opus).")
    p_start.set_defaults(func=cmd_start)

    p_status = sub.add_parser("status", help="Show both agents' current status.")
    p_status.add_argument("--watch", action="store_true", help="Keep refreshing until both agents finish.")
    p_status.add_argument("--interval", type=int, default=30, help="Seconds between refreshes (default 30).")
    p_status.set_defaults(func=cmd_status)

    p_stop = sub.add_parser("stop", help="Stop both agents.")
    p_stop.set_defaults(func=cmd_stop)

    p_collect = sub.add_parser("collect", help="Pull results, submit flags, run auto-attest, archive.")
    p_collect.add_argument("--archive-name", help="Archive folder name (default: run-results-<date>-<round>).")
    p_collect.set_defaults(func=cmd_collect)

    p_check = sub.add_parser("check", help="Verify GNS3 VM/Kali/targets/keys are all reachable before `start`.")
    p_check.set_defaults(func=cmd_check)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
