#!/bin/sh
# Sets up an Alpine Linux VM so that it boots straight into Sentinel,
# with no username/password prompt.
#
# Run as root from the project folder:
#     sh alpine/setup_alpine.sh
#
# What it does:
#   1. installs the compiler, make, gdb, valgrind and git
#   2. builds Sentinel and copies it to /usr/local/bin
#   3. creates an unprivileged user "sentinel" whose login shell IS the program
#      (so there is no way to reach a normal shell from tty1)
#   4. changes /etc/inittab so tty1 logs in as "sentinel" automatically
#
# To undo step 4:  cp /etc/inittab.before-sentinel /etc/inittab
# Maintenance: press Alt+F2 to get a normal login prompt on tty2 and log in as root.

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

echo "==> Installing tools"
apk update
apk add build-base gdb valgrind git

echo "==> Building Sentinel"
make clean all
make install PREFIX=/usr/local
install -m 755 alpine/sentinel-shell /usr/local/bin/sentinel-shell
install -m 755 alpine/sentinel-autologin /usr/local/bin/sentinel-autologin

echo "==> Creating the sentinel user"
grep -qx /usr/local/bin/sentinel-shell /etc/shells || echo /usr/local/bin/sentinel-shell >> /etc/shells
if ! id sentinel >/dev/null 2>&1; then
    adduser -D -h /var/lib/sentinel -s /usr/local/bin/sentinel-shell sentinel
fi
mkdir -p /var/lib/sentinel
chown sentinel:sentinel /var/lib/sentinel
chmod 700 /var/lib/sentinel

echo "==> Making tty1 log in automatically"
[ -f /etc/inittab.before-sentinel ] || cp /etc/inittab /etc/inittab.before-sentinel
sed -i 's|^tty1::respawn:.*|tty1::respawn:/sbin/getty -n -l /usr/local/bin/sentinel-autologin 38400 tty1|' /etc/inittab
grep '^tty1' /etc/inittab

echo
echo "Done. Type 'reboot' - the VM should start directly in Sentinel."
