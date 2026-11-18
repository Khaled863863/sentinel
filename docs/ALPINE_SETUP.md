# Alpine VM setup

Goal: when the VM starts, Sentinel appears on the screen with no login prompt.

## 1. Create the VM

1. Download the **Standard** x86_64 ISO from https://alpinelinux.org/downloads/
2. In VirtualBox (or VMware): new VM, type Linux / Other Linux 64-bit, 512 MB RAM, 4 GB disk.
3. Boot the ISO, log in as `root` (no password), and run `setup-alpine`.
   - Keyboard: `us`. Hostname: e.g. `sentinel-vm`. Network: `eth0`, `dhcp`.
   - Set a root password (you will need it for maintenance).
   - Disk: choose `sda`, then `sys`.
4. When it finishes, type `poweroff`, remove the ISO from the VM settings, and start the VM again.

## 2. Copy the project into the VM

The easiest way is git:

```
apk add git
git clone https://github.com/<your-account>/sentinel.git
cd sentinel
```

## 3. Run the setup script

```
sh alpine/setup_alpine.sh
reboot
```

After the reboot, Sentinel should be the first thing on the screen. Take a screenshot of this.

How it works (you will be asked this in the presentation):

- `/etc/inittab` tells the system what to run on each terminal. The script changes the `tty1`
  line to `getty -n -l /usr/local/bin/sentinel-autologin`, so getty does not ask for a name
  and runs our autologin script instead.
- `sentinel-autologin` runs `login -f sentinel`, which logs in the `sentinel` user without a password.
- The `sentinel` user's login shell is `sentinel-shell`, which starts Sentinel. There is no normal
  shell, so exiting Sentinel just starts it again (the `respawn` in inittab).
- The `sentinel` user is not root and has no sudo, so even if someone broke out of the program
  they could not change the system. Auto-login is a security risk; this limits the damage.

Maintenance: press **Alt+F2** for a normal login prompt on tty2 and log in as root.
To undo: `cp /etc/inittab.before-sentinel /etc/inittab`.

## 4. Part 3: two VMs on a network

1. Clone the VM (VirtualBox: right click, Clone, "Generate new MAC addresses").
2. On **both** VMs, set Adapter 2 to **Host-only Adapter** (or both to the same **NAT Network**).
3. Start both and find each IP with `ip addr` (on tty2 as root). Run `udhcpc -i eth1` if eth1 has no address.
4. On the server VM (tty2, as root):
   ```
   SENTINEL_DIR=/var/lib/sentinel sentinel-server 5555
   ```
   Or start it automatically (optional):
   ```
   install -m 755 alpine/sentinel-server.initd /etc/init.d/sentinel-server
   rc-update add sentinel-server default
   rc-service sentinel-server start
   ```
5. On the client VM (tty2): `sentinel-client <server-ip> 5555`, then type `HELP`.

Both VMs must use the same key: the default key is built in, or set `SENTINEL_KEY` to the same
value on both sides.

## If the build fails on Alpine

The code was tested with gcc 13 and clang on Ubuntu, and only uses standard POSIX functions.
If gcc on Alpine shows an error, check that `build-base` is installed (`apk add build-base`)
and run `make clean all` again. Send the exact error message if it still fails.
