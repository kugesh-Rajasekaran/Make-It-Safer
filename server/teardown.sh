#!/bin/sh
# Make-It-Safer server removal (format 1): deletes the "mis" user, the
# collector and the sshd settings that setup added. Nothing else is touched.
set -eu

MIS_USER=mis
MIS_HOME=/var/lib/mis
LIB_DIR=/usr/local/lib/mis
MARKER=$MIS_HOME/.managed-by-make-it-safer
MAIN=/etc/ssh/sshd_config
DROPIN=/etc/ssh/sshd_config.d/50-mis.conf

say() { printf 'mis-teardown: %s\n' "$*"; }
fail() { printf 'mis-teardown: ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "must run as root"
[ -e "$MARKER" ] || fail "no Make-It-Safer setup found on this server; nothing was changed"
SSHD=$(command -v sshd || echo /usr/sbin/sshd)

reload_sshd() {
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ssh 2>/dev/null; then
        systemctl reload ssh
    elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet sshd 2>/dev/null; then
        systemctl reload sshd
    elif [ -f /run/sshd.pid ]; then
        kill -HUP "$(cat /run/sshd.pid)"
    fi
}

rm -f "$DROPIN"
if grep -q '^# BEGIN make-it-safer$' "$MAIN"; then
    cp -p "$MAIN" "$MAIN.mis-bak"
    sed -i '/^# BEGIN make-it-safer$/,/^# END make-it-safer$/d' "$MAIN"
    if ! "$SSHD" -t; then
        mv -f "$MAIN.mis-bak" "$MAIN"
        fail "sshd settings were invalid after removing the block; restored them"
    fi
    rm -f "$MAIN.mis-bak"
fi
"$SSHD" -t || fail "sshd settings are invalid; please check $MAIN"
reload_sshd

# userdel refuses while the user has a process, so end its sessions and wait.
# The home directory holds the marker: it goes only after the user is gone.
pkill -KILL -u "$MIS_USER" >/dev/null 2>&1 || true
i=0
while pgrep -u "$MIS_USER" >/dev/null 2>&1 && [ "$i" -lt 10 ]; do
    sleep 1
    i=$((i + 1))
done
if id "$MIS_USER" >/dev/null 2>&1; then
    userdel "$MIS_USER" || fail "could not remove the '$MIS_USER' user; stop its processes and run: userdel $MIS_USER"
fi
rm -rf "$MIS_HOME" "$LIB_DIR"
say "done: the '$MIS_USER' user and its settings are gone"
