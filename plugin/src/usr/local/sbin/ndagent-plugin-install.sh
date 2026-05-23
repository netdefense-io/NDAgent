#!/bin/sh
#
# ndagent-plugin-install.sh — detached pkg(8) wrapper for PLUGIN_INSTALL.
#
# Args:
#   $1 — pkg name (os-netdefense / os-netdefense-qa / os-netdefense-dev)
#   $2 — optional semver (e.g. 1.4.5); empty = upgrade to latest
#   $3 — task_id (NDManager's task identifier; used as the drop-file name)
#
# Started by HandlePluginInstall (internal/tasks/plugin_install.go) via
# exec.Command + SysProcAttr.Setsid so it survives the pre-deinstall
# `rc.d ndagent stop` triggered by the pkg upgrade transaction itself.
# pkg's post-install runs `rc.d configd restart` then `rc.d ndagent start`,
# bringing the new agent binary online — at which point the boot-time
# drain in internal/core/lifecycle.go reads the drop file we write here
# (/var/db/ndagent/pending-results/<task_id>.json), reconciles the pkg
# exit code into the local task store, and replays the COMPLETED/FAILED
# task_response to NDBroker. The agent never sends a final response
# from the originating process — it's killed by pkg's pre-deinstall.
#
# Output is logged to /var/log/ndagent-plugin-install.log so failures are
# inspectable post-mortem (the agent is dead by then). The 2s lead-in
# gives the parent agent process time to flush its IN_PROGRESS WS frame
# and exit before pkg starts the upgrade transaction.

set -u

LOG=/var/log/ndagent-plugin-install.log
DROP_DIR=/var/db/ndagent/pending-results
PKG_NAME="${1:?missing pkg name}"
PKG_VERSION="${2:-}"
TASK_ID="${3:-}"

# Convert semver X.Y.Z -> FreeBSD pkg-version X.Y_Z. The os-netdefense*
# packages use `1.4_5` style internally (see Makefile VERSION_FREEBSD);
# `pkg install` rejects the dot form with "no packages available".
# Replaces only the LAST "." so `1.4.5` -> `1.4_5` and `2.0.0-rc1` ->
# `2.0_0-rc1` (rc1 keeps any FreeBSD-side prerelease semantics intact).
to_pkg_version() {
    echo "$1" | /usr/bin/sed 's/\.\([^.]*\)$/_\1/'
}

# write_drop_file writes a small JSON record with the pkg exit code to
# /var/db/ndagent/pending-results/<task_id>.json via atomic rename. The
# new agent process picks it up on boot. Skipped if no TASK_ID was
# passed (older NDAgent caller — fall back to the broker's expiry path).
write_drop_file() {
    rc="$1"
    if [ -z "$TASK_ID" ]; then
        return 0
    fi
    /bin/mkdir -p "$DROP_DIR"
    /bin/chmod 0700 "$DROP_DIR" 2>/dev/null || true
    tmp=$(/usr/bin/mktemp "${DROP_DIR}/.${TASK_ID}.XXXXXX") || return 1
    # JSON encoding of the message is intentionally minimal — the
    # message is reconstructed by the agent's reconciler from exit_code
    # when it's empty. If the helper needs to surface a specific
    # message in the future, this is the place to escape and emit it.
    if [ "$rc" -eq 0 ]; then
        msg="Plugin install completed; pkg exit 0"
    else
        msg="Plugin install failed; pkg exit ${rc}"
    fi
    printf '{"task_id":"%s","exit_code":%d,"message":"%s"}\n' \
        "$TASK_ID" "$rc" "$msg" > "$tmp"
    /bin/chmod 0600 "$tmp"
    /bin/mv -f "$tmp" "${DROP_DIR}/${TASK_ID}.json"
}

{
    printf '\n=== ndagent-plugin-install %s pkg=%s version=%s task_id=%s ===\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PKG_NAME" "${PKG_VERSION:-latest}" "${TASK_ID:-<none>}"

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

    # Persist the pkg outcome before bringing the agent back up. The
    # write_drop_file step is best-effort: a failure here just means the
    # broker will fall back to its 15-min PENDING expiry, which is
    # noisier but still correct.
    if ! write_drop_file "$rc"; then
        printf 'WARN: failed to write drop file at %s/%s.json\n' "$DROP_DIR" "$TASK_ID"
    fi

    # On pkg failure the post-install never runs, so the rc.d ndagent
    # restart never fires and the agent stays down. Bring the agent
    # back ourselves so the boot-time drain can deliver the FAILED
    # response within seconds. Idempotent on success (pkg's own
    # post-install already started it; this is a no-op).
    /usr/local/etc/rc.d/ndagent start || true

    printf '=== exit=%d ===\n' "$rc"
    exit "$rc"
} >> "$LOG" 2>&1
