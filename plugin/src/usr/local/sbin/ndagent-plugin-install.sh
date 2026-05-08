#!/bin/sh
#
# ndagent-plugin-install.sh — detached pkg(8) wrapper for PLUGIN_INSTALL.
#
# Args:
#   $1 — pkg name (os-netdefense / os-netdefense-qa / os-netdefense-dev)
#   $2 — optional semver (e.g. 1.4.5); empty = upgrade to latest
#
# Started by HandlePluginInstall (internal/tasks/plugin_install.go) via
# exec.Command + SysProcAttr.Setsid so it survives the pre-deinstall
# `rc.d ndagent stop` triggered by the pkg upgrade transaction itself.
# pkg's post-install runs `rc.d configd restart` then `rc.d ndagent start`,
# bringing the new agent binary online — at which point its first WS
# auth carries the new version and NDBroker resolves the in-flight task.
#
# Output is logged to /var/log/ndagent-plugin-install.log so failures are
# inspectable post-mortem (the agent is dead by then). The 2s lead-in
# gives the parent agent process time to flush its IN_PROGRESS WS frame
# and exit before pkg starts the upgrade transaction.

set -u

LOG=/var/log/ndagent-plugin-install.log
PKG_NAME="${1:?missing pkg name}"
PKG_VERSION="${2:-}"

# Convert semver X.Y.Z -> FreeBSD pkg-version X.Y_Z. The os-netdefense*
# packages use `1.4_5` style internally (see Makefile VERSION_FREEBSD);
# `pkg install` rejects the dot form with "no packages available".
# Replaces only the LAST "." so `1.4.5` -> `1.4_5` and `2.0.0-rc1` ->
# `2.0_0-rc1` (rc1 keeps any FreeBSD-side prerelease semantics intact).
to_pkg_version() {
    echo "$1" | /usr/bin/sed 's/\.\([^.]*\)$/_\1/'
}

{
    printf '\n=== ndagent-plugin-install %s pkg=%s version=%s ===\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PKG_NAME" "${PKG_VERSION:-latest}"

    sleep 2

    /usr/sbin/pkg update

    if [ -n "$PKG_VERSION" ]; then
        FBSD_VERSION=$(to_pkg_version "$PKG_VERSION")
        printf 'Resolved pkg-version: %s\n' "$FBSD_VERSION"
        /usr/sbin/pkg install -y "${PKG_NAME}-${FBSD_VERSION}"
    else
        /usr/sbin/pkg upgrade -y "$PKG_NAME"
    fi
    rc=$?

    # On pkg failure the post-install never runs, so the rc.d ndagent
    # restart never fires and the agent stays down — leaving the broker
    # to time out at expires_at instead of resolving FAILED on reauth.
    # Bring the agent back ourselves so the broker can mark the task
    # FAILED with the right reason within seconds. Idempotent on success
    # (pkg's own post-install already started it; this is a no-op).
    /usr/local/etc/rc.d/ndagent start || true

    printf '=== exit=%d ===\n' "$rc"
    exit "$rc"
} >> "$LOG" 2>&1
