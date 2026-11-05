#!/bin/sh
# Make-It-Safer collector, output format 1. Installed as /usr/local/lib/mis/collect.
#
# sshd forces this script for the read-only "mis" user, whatever the client
# asks to run. It only reads: OS release, running kernel, the reboot flag,
# its own groups and the installed packages. It ignores all input.
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin

field() { sed -n "s/^$1=//p" /etc/os-release | head -n 1 | tr -d '"'; }

echo "mis-collect 1"
echo "os-id=$(field ID)"
echo "os-version=$(field VERSION_ID)"
echo "kernel=$(uname -r)"
echo "arch=$(dpkg --print-architecture 2>/dev/null)"
if [ -e /var/run/reboot-required ]; then echo "reboot-required=yes"; else echo "reboot-required=no"; fi
echo "groups=$(id -Gn)"
dpkg-query -W -f='pkg\t${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n'
