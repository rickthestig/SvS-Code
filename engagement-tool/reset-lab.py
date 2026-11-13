"""Stop, reset, boot, and restore blue administrator access for weak/IoT targets."""
from lab import *
import argparse, shlex, time

NODES = {'weak': ('b224b412-6fbd-4741-8f02-4d212993a5c1', '10.10.30.20'),
         'iot': ('6bd8f977-f559-43ff-916e-472176701fc0', '10.10.40.20')}

def restore_blue(vm, ip, public_key, timeout=180):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        client = paramiko.SSHClient()
        client.load_host_keys(str(WORK / 'target-known-hosts'))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            channel = vm.get_transport().open_channel('direct-tcpip', (ip, 22), ('127.0.0.1', 0), timeout=5)
            client.connect(ip, username='labadmin', key_filename=str(WORK / 'lab-admin-key'),
                           sock=channel, look_for_keys=False, allow_agent=False, timeout=5,
                           banner_timeout=5, auth_timeout=5)
        except paramiko.BadHostKeyException:
            client.close()
            raise
        except (OSError, paramiko.SSHException) as exc:
            client.close()
            last_error = exc
            time.sleep(3)
            continue
        try:
            script = '''set -eu
id defender >/dev/null 2>&1 || useradd -m -s /bin/bash defender
install -d -m 700 -o defender -g defender /home/defender/.ssh
touch /home/defender/.ssh/authorized_keys
grep -qxF -- KEY /home/defender/.ssh/authorized_keys || printf '%s\\n' KEY >> /home/defender/.ssh/authorized_keys
chown defender:defender /home/defender/.ssh/authorized_keys
chmod 600 /home/defender/.ssh/authorized_keys
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
printf 'defender ALL=(ALL) NOPASSWD: ALL\\n' > "$tmp"
visudo -cf "$tmp"
install -m 440 -o root -g root "$tmp" /etc/sudoers.d/thesis-defender
'''.replace('KEY', shlex.quote(public_key))
            print(run(client, 'sudo -n sh -c ' + shlex.quote(script)), flush=True)
        finally:
            client.close()
        verify = paramiko.SSHClient()
        verify.load_host_keys(str(WORK / 'target-known-hosts'))
        verify.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            channel = vm.get_transport().open_channel('direct-tcpip', (ip, 22), ('127.0.0.1', 0), timeout=5)
            verify.connect(ip, username='defender', key_filename=str(pathlib.Path.home()/'.ssh/thesis_blue'),
                           sock=channel, look_for_keys=False, allow_agent=False, timeout=5)
            result = run(verify, 'sudo -n id -u').strip()
            if result != '0': raise RuntimeError('Blue root verification failed: ' + result)
            print('Blue SSH and passwordless sudo verified for ' + ip, flush=True)
            return
        finally:
            verify.close()
    raise RuntimeError(f'Target did not become accessible in {timeout}s: {last_error}')

RESET_SCRIPT = r'''#!/bin/bash
# Run on the GNS3 VM only, after stopping the selected target in GNS3.
set -euo pipefail
case "${1:-}" in
 weak) node=b224b412-6fbd-4741-8f02-4d212993a5c1 ;;
 iot) node=6bd8f977-f559-43ff-916e-472176701fc0 ;;
 ms3) node=9144998a-7d83-44aa-a43b-1f5ecc1d79fd ;;
 *) echo 'Usage: bash reset-target.sh weak|iot|ms3'; exit 2 ;;
esac
project=47184b19-f33d-4e64-bb7b-239f28108e69
active="/opt/gns3/projects/$project/project-files/qemu/$node"
if [[ "$1" == ms3 ]]; then baseline="/home/gns3/codex-tournament/baselines/20261112-ms3/ms3"; else baseline="/home/gns3/codex-tournament/baselines/20261009-ready/$1"; fi
[[ "$(realpath "$active")" == "$active" ]] || { echo 'Unexpected active path'; exit 1; }
[[ "$(realpath "$baseline")" == "$baseline" ]] || { echo 'Unexpected baseline path'; exit 1; }
if pgrep -af qemu-system | grep -F -- "-uuid $node" >/dev/null; then
 echo 'Target is still running. Stop it in GNS3 first.'; exit 1
fi
(cd "$baseline" && sha256sum -c SHA256SUMS)
qemu-img check "$baseline/hda_disk.qcow2"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
rollback="$active/pre-reset/$stamp"
mkdir -p "$rollback"
qemu-img create -f qcow2 -F qcow2 -b "$baseline/hda_disk.qcow2" "$active/hda_disk.reset.qcow2"
mv "$active/hda_disk.qcow2" "$rollback/hda_disk.qcow2"
mv "$active/hda_disk.reset.qcow2" "$active/hda_disk.qcow2"
chmod 644 "$active/hda_disk.qcow2"
# UEFI targets keep a firmware-variables file; BIOS ones (Metasploitable 3) have none.
if [[ -f "$baseline/OVMF_VARS_4M.fd" ]]; then
 mv "$active/OVMF_VARS_4M.fd" "$rollback/OVMF_VARS_4M.fd"
 cp "$baseline/OVMF_VARS_4M.fd" "$active/OVMF_VARS_4M.fd"
 chmod 644 "$active/OVMF_VARS_4M.fd"
fi
sync
echo "Disk reset complete for $1. Controller will start the target."
echo "Pre-reset files retained at $rollback"
echo 'The restored disk depends on the immutable baseline. Keep that baseline in its recorded location.'
'''

def run_reset(vm, name):
    stdin, stdout, stderr = vm.exec_command("bash -s -- " + name, timeout=180)
    stdin.write(RESET_SCRIPT)
    stdin.flush()
    stdin.channel.shutdown_write()
    output, errors = stdout.read().decode(), stderr.read().decode()
    if stdout.channel.recv_exit_status() != 0:
        raise RuntimeError("Baseline reset failed: " + errors + output)
    return output


def reset_target(vm, name, public_key, restore_only=False):
    node, ip = NODES[name]
    if not restore_only:
        state = api("GET", f"projects/{PROJECT}/nodes/{node}")["status"]
        if state != "stopped":
            print(f"Stopping {name}...", flush=True)
            api("POST", f"projects/{PROJECT}/nodes/{node}/stop")
            deadline = time.monotonic() + 60
            while api("GET", f"projects/{PROJECT}/nodes/{node}")["status"] != "stopped":
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"{name} did not stop; disk reset was not attempted")
                time.sleep(1)
        print(run_reset(vm, name), flush=True)
        api("POST", f"projects/{PROJECT}/nodes/{node}/start")
        print(f"{name} started; restoring blue access...", flush=True)
    restore_blue(vm, ip, public_key)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', nargs='?', default='all', choices=['all', *NODES], help='Default: reset both weak and IoT')
    parser.add_argument('--restore-only', action='store_true', help='Reapply and verify blue access without resetting or restarting the target')
    args = parser.parse_args()
    public_key = (pathlib.Path.home()/'.ssh/thesis_blue.pub').read_text().strip()
    for path in [WORK/'lab-admin-key', WORK/'target-known-hosts', pathlib.Path.home()/'.ssh/thesis_blue']:
        if not path.is_file(): raise RuntimeError('Required file missing: ' + str(path))
    vm = connect()
    try:
        targets = list(NODES) if args.target == 'all' else [args.target]
        for name in targets:
            reset_target(vm, name, public_key, args.restore_only)
        print('Reset workflow complete.', flush=True)
    finally:
        vm.close()

if __name__ == '__main__':
    main()


