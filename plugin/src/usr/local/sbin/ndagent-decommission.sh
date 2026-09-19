#!/bin/sh
#
# ndagent-decommission.sh — detached uninstall helper for self-decommission.
#
# Args:
#   $1 — pkg name this build belongs to
#        (os-netdefense / os-netdefense-qa / os-netdefense-dev)
#
# Started by the agent's decommission sequence (internal/tasks/decommission.go)
# via exec.Command + SysProcAttr.Setsid, exactly like ndagent-plugin-install.sh.
# Setsid is what makes this survivable: `pkg delete` runs the package's own
# pre-deinstall hook, which does `rc.d ndagent stop` — a SIGTERM to the agent's
# process group. Without its own session this helper would be in that group and
# would die halfway through removing the package that is killing it.
#
# By the time this runs, the agent has already reconciled every managed
# OPNsense object away, deprovisioned the two NetDefense accounts and cleared
# the plugin settings. The account deprovision is repeated here as a
# belt-and-braces pass (it is idempotent) because it is the one piece of
# cleanup that leaves a live admin credential behind when it does not happen.
# What is left after that is the irreversible half:
#
#   1. wait (bounded) for the agent process to exit
#   2. stop ndagent               (idempotent)
#   3. deprovision the two NetDefense OPNsense accounts, locally — the
#      plugin and its PHP are still installed at this point, and this is
#      the last moment they are
#   4. pkg delete -y <this channel's package, plus any sibling channel)
#   5. remove the NetDefense pkg repo config(s) and fingerprint dir
#      (mirrors remove_legacy_repo() in ndagent-repo/install.sh)
#   6. rm -rf /var/db/ndagent   (identity, pinned keys, replay watermarks)
#
# It NEVER restarts ndagent — that is the one line that separates this helper
# from its PLUGIN_INSTALL sibling. There is nothing left to start: the device
# row is gone and the binary is being removed.
#
# Output goes to /var/log/ndagent-decommission.log, the same file the agent
# wrote its half of the sequence to. That file lives outside /var/db/ndagent
# on purpose and is the only post-mortem record of what happened here.

set -u

LOG=/var/log/ndagent-decommission.log
PKG_NAME="${1:?missing pkg name}"

REPO_CONF_DIR=/usr/local/etc/pkg/repos
FINGERPRINT_DIR=/usr/local/etc/pkg/fingerprints
STATE_DIR=/var/db/ndagent
PIDFILE=/var/run/ndagent.pid
PHP=/usr/local/bin/php
CONFIGURE_PHP=/usr/local/opnsense/scripts/OPNsense/NetDefense/configure.php
RC_SCRIPT=/usr/local/etc/rc.d/ndagent

# Bounded wait for the agent to go away on its own. It requested shutdown
# immediately after forking us, so this is normally a second or two; the
# ceiling stops a wedged agent from parking this helper forever, and step 2
# stops it for real either way.
wait_for_agent_exit() {
    i=0
    while [ "$i" -lt 30 ]; do
        if [ ! -f "$PIDFILE" ]; then
            printf 'agent pidfile gone after %ss\n' "$i"
            return 0
        fi
        pid=$(cat "$PIDFILE" 2>/dev/null || echo "")
        if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
            printf 'agent process gone after %ss\n' "$i"
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    printf 'WARN: agent still running after %ss; continuing anyway\n' "$i"
    return 0
}

# Stop the service without depending on ndagent_enable being set in
# /etc/rc.conf. `rc.d ndagent stop` refuses on a box where the knob is unset
# ("Cannot 'stop' ndagent. Set ndagent_enable to YES ... or use 'onestop'"),
# which is the normal state on a device configured through the plugin rather
# than by hand. `onestop` runs the stop regardless. Both are no-ops when the
# service is not running, so this stays idempotent either way.
stop_agent() {
    [ -f "$RC_SCRIPT" ] || return 0
    printf 'Stopping ndagent\n'
    "$RC_SCRIPT" onestop || printf 'WARN: rc.d ndagent onestop returned non-zero\n'
}

# Remove the two NetDefense-owned OPNsense accounts, locally.
#
# The agent already ran this exact call before forking us. It is repeated
# here because this is the last moment the plugin's PHP exists on the box:
# if the agent's pass failed (config lock contention, a wedged configd, an
# agent killed mid-sequence), the alternative is a decommissioned device
# keeping a page-all `netdefense-agent` user with a live API key in
# config.xml forever. The call is idempotent — a second run when the first
# one worked reports removed:false and changes nothing.
#
# Never fatal: a failure here must not stop the package coming off.
deprovision_accounts() {
    if [ ! -x "$PHP" ] || [ ! -f "$CONFIGURE_PHP" ]; then
        printf 'WARN: %s or %s missing; skipping account deprovision\n' "$PHP" "$CONFIGURE_PHP"
        return 0
    fi
    printf 'Deprovisioning NetDefense OPNsense accounts\n'
    "$PHP" "$CONFIGURE_PHP" --deprovision-accounts --json ||
        printf 'WARN: configure.php --deprovision-accounts returned non-zero\n'
}

# Remove the package for this channel, and sweep any sibling channel package
# that somehow coexists. The three channel packages declare mutual
# product_conflicts so normally only one is installed, but a decommission that
# leaves a NetDefense package behind has failed at its only job.
remove_packages() {
    for name in $(/usr/sbin/pkg query '%n' 2>/dev/null | grep '^os-netdefense' || true); do
        printf 'Removing package %s\n' "$name"
        /usr/sbin/pkg delete -y "$name" || printf 'WARN: pkg delete %s failed\n' "$name"
    done

    # Belt and braces: if the query above returned nothing (pkg database
    # unreadable, say), still try the name we were told to remove.
    if /usr/sbin/pkg info -e "$PKG_NAME" 2>/dev/null; then
        printf 'Removing package %s (fallback path)\n' "$PKG_NAME"
        /usr/sbin/pkg delete -y "$PKG_NAME" || printf 'WARN: pkg delete %s failed\n' "$PKG_NAME"
    fi
}

# Mirror of install.sh's repo registration, in reverse: the current
# capitalised names, the legacy lowercase ones, and the timestamped backups
# configure_repo() leaves behind.
remove_repo() {
    for f in "${REPO_CONF_DIR}/NetDefense.conf" "${REPO_CONF_DIR}/netdefense.conf"; do
        if [ -f "$f" ]; then
            printf 'Removing repo config %s\n' "$f"
            rm -f "$f" || printf 'WARN: could not remove %s\n' "$f"
        fi
    done
    for f in "${REPO_CONF_DIR}"/NetDefense.conf.backup.* "${REPO_CONF_DIR}"/netdefense.conf.backup.*; do
        [ -e "$f" ] || continue
        printf 'Removing repo config backup %s\n' "$f"
        rm -f "$f" || printf 'WARN: could not remove %s\n' "$f"
    done
    for d in "${FINGERPRINT_DIR}/NetDefense" "${FINGERPRINT_DIR}/netdefense"; do
        if [ -d "$d" ]; then
            printf 'Removing fingerprint dir %s\n' "$d"
            rm -rf "$d" || printf 'WARN: could not remove %s\n' "$d"
        fi
    done
}

# Identity, pinned NDManager keys, replay watermarks, task registry, pending
# results. This is what makes a later reinstall a genuinely new device rather
# than one carrying a dispatch_seq watermark no fresh registration can clear.
remove_state() {
    if [ -d "$STATE_DIR" ]; then
        printf 'Removing agent state %s\n' "$STATE_DIR"
        rm -rf "$STATE_DIR" || printf 'WARN: could not remove %s\n' "$STATE_DIR"
    fi
    if [ -f /usr/local/etc/ndagent.conf ]; then
        printf 'Removing rendered config /usr/local/etc/ndagent.conf\n'
        rm -f /usr/local/etc/ndagent.conf || printf 'WARN: could not remove ndagent.conf\n'
    fi
}

{
    printf '\n=== ndagent-decommission %s pkg=%s ===\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PKG_NAME"

    # Let the parent flush its final log lines and exit, the same 2s lead-in
    # the plugin-install helper uses.
    sleep 2

    wait_for_agent_exit

    stop_agent
    deprovision_accounts

    remove_packages
    remove_repo
    remove_state

    left=$(/usr/sbin/pkg query '%n' 2>/dev/null | grep -c '^os-netdefense' || true)
    printf '=== decommission complete: netdefense packages remaining=%s ===\n' "${left:-unknown}"
} >> "$LOG" 2>&1

exit 0
