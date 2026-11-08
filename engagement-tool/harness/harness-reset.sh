#!/bin/bash
# Resets the attacker harness at ~/harness to a blank state between engagements.
# Clears run-specific content (loot/logs/scans/scope) and this harness's own Claude Code session
# history, but preserves the harness directory structure, README, and this script itself.
set -euo pipefail
HARNESS="$HOME/harness"

mkdir -p "$HARNESS"/loot "$HARNESS"/logs "$HARNESS"/scans "$HARNESS"/scope
rm -rf "${HARNESS:?}"/loot/* "$HARNESS"/logs/* "$HARNESS"/scans/* "$HARNESS"/scope/* 2>/dev/null || true

# Claude Code names a project's session-history directory after the cwd path with slashes turned
# into dashes -- e.g. /home/kali/harness -> -home-kali-harness. Clear it so a new run starts with
# no memory of the last one.
PROJECT_DIR="$HOME/.claude/projects/$(echo "$HARNESS" | sed 's/\//-/g')"
rm -rf "$PROJECT_DIR" 2>/dev/null || true

# An agent can (and has) dropped recon output directly in $HOME instead of ~/harness, despite being
# told where things go -- that's a stale head-start for the next run, not just clutter. Sweep any
# loose top-level files out of $HOME too (not directories, not dotfiles -- this account's dotfiles
# are infrastructure, not run output). Some of this can be root-owned (sudo'd tool output); this
# account's sudo needs a password non-interactively, so pipe it rather than silently no-op.
find "$HOME" -maxdepth 1 -type f ! -name '.*' -print0 2>/dev/null | xargs -0 -r rm -f 2>/dev/null
find "$HOME" -maxdepth 1 -type f ! -name '.*' 2>/dev/null | while read -r f; do
  echo kali | sudo -S -p '' rm -f "$f" 2>/dev/null
done

# Shell history is the same leak as the stray-files one above, just harder to spot: this box's
# original bootstrap (routing setup, target IP probes, red-key provisioning) is sitting in plain
# text in .zsh_history, and "check my own shell history" is a completely normal recon move -- so
# an agent reading it gets the subnet and target IPs handed to it for free instead of discovering
# them. Truncate history files and the SSH known_hosts cache (which would otherwise reveal exactly
# which IPs were previously contacted) every reset, not just on first setup.
: > "$HOME/.zsh_history" 2>/dev/null || true
: > "$HOME/.bash_history" 2>/dev/null || true
rm -f "$HOME/.ssh/known_hosts" 2>/dev/null || true

echo "Harness reset: loot/, logs/, scans/, scope/ cleared; prior Claude session history removed."
echo "Stray top-level files in \$HOME (outside ~/harness) swept too."
echo "Shell history and SSH known_hosts cleared."
echo "Harness structure, README, and this script preserved at $HARNESS."
