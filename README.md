# Red and blue team lab runner

Use this kit on the organizer’s Windows controller to run a timed trial in a prepared GNS3 lab, collect evidence and scores, and reset the Ubuntu targets afterward. Run all commands from the repository root. The kit assumes you already have the isolated topology, challenge fixtures, working management routes, SSH accounts, and frozen baseline disks. Connecting an AI participant requires your own adapter for the local bridge API.

## Set up once

1. Install Python 3.11 or later and the OpenSSH client. Create the environment and local config files in PowerShell:

       python -m venv .venv
       .\.venv\Scripts\Activate.ps1
       python -m pip install -r requirements.txt
       Copy-Item ssh_config.example ssh_config
       Copy-Item reset.example.json reset.local.json
       New-Item -ItemType Directory -Force private

2. Restrict the private directory to the organizer using the controller’s filesystem permissions. Edit ssh_config with your actual hostnames, usernames and dedicated key paths. Verify host fingerprints from the VM consoles and record the jump host and targets in ~/.ssh/thesis_known_hosts. Test each intended alias, for example:

       ssh -F ssh_config thesis-kali id
       ssh -F ssh_config thesis-weak "sudo -n id -u"
       ssh -F ssh_config thesis-pfsense id

3. Configure reset.local.json with the GNS3 project and target UUIDs, jump host, key, local GNS3 server configuration, and absolute disk paths. The baseline root must contain weak/ and iot/, each with SHA256SUMS, hda_disk.qcow2 and OVMF_VARS_4M.fd. The jump account needs permission to swap disks on the GNS3 VM. Check each UUID against its intended node before the first reset.

4. For reset provisioning, place the organizer’s existing Linux maintenance key in private/lab-admin-key. The frozen guests must accept that key for labadmin with passwordless sudo. Place verified OpenSSH host-key entries for the jump hostname and both target IPs in private/target-known-hosts. Keep the defender key pair at ~/.ssh/thesis_blue and ~/.ssh/thesis_blue.pub. These credentials are supplied locally by the operator.

5. Run the offline tests:

       python -m unittest discover -s tests

## Run a trial

1. Verify the starting baseline and SSH connectivity. Prepare a fresh round and generate its private flag bundle:

       python trials.py prepare pilot-001 --condition ai-versus-ai --seconds 1800
       python scoring.py --db private/trials/pilot-001/score.db create pilot-001 --seconds 86400 --output private/trials/pilot-001/flags.json

2. Transfer install_flags.py and the round’s flags.json securely to the freshly restored Ubuntu-Weak guest. On that guest, run `sudo python3 install_flags.py flags.json`. Verify installation and remove the transferred flag bundle before participant access.
3. In private/trials/pilot-001, record the baseline hash, verification time and flag checks in flags-installed.txt. Review the generated participant scopes and target aliases. Set baseline_verified and connectivity_verified in trial.json to true after checking them.
4. Start the timer and participant bridges:

       python trials.py run private/trials/pilot-001

5. Connect each participant through its matching role adapter and token. The default scored blue scope is pfSense and Ubuntu-Weak. During the round, the organizer records legitimate-service checks and referee evidence. Save scores.json, logs and evidence before resetting. See [experiment conditions](EXPERIMENTS.md) for the human-terminal workflow and [operator guide](OPERATOR_GUIDE.md) for bridge calls, scoring and evidence commands.

## Reset after a test

    python reset-lab.py

The command stops Ubuntu-Weak and Ubuntu-IoT in turn, verifies the baseline checksums, preserves each previous disk under pre-reset, restores the baseline, boots the guest, and verifies blue SSH and passwordless sudo. Append weak or iot to select a single guest. If only access restoration needs retrying after boot, use `python reset-lab.py weak --restore-only`. Changes made during a trial to pfSense, Kali or UbuntuBase require separate recovery.

## Upload to Git

Use this folder as the repository root. Keep machine-specific config, credentials, VM disks and trial evidence outside the commit. The shipped .gitignore covers the documented local paths. To review the initial upload:

    git init
    git add .
    git diff --cached --name-only

After reviewing the staged files, commit them and push to your chosen remote.
