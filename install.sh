#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# One-command setup: build the driver, install it, install Otter, and grant
# access to Samsung download-mode devices so nothing needs to run as root.
set -e
cd "$(dirname "$0")"

echo "==> building odin3-linux"
make

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required for the Otter GUI" >&2
    exit 1
fi
if ! python3 -c 'import gi; gi.require_version("Gtk","3.0")' >/dev/null 2>&1; then
    echo "warning: PyGObject/GTK3 not found - the driver will work, Otter will not." >&2
    echo "         Debian/Ubuntu: sudo apt install python3-gi gir1.2-gtk-3.0" >&2
    echo "         Fedora:        sudo dnf install python3-gobject gtk3" >&2
    echo "         Arch:          sudo pacman -S python-gobject gtk3" >&2
fi

echo "==> installing (sudo)"
sudo install -Dm755 odin3-linux   /usr/local/bin/odin3-linux
sudo install -Dm755 otter         /usr/local/bin/otter
sudo install -Dm644 otter.desktop /usr/local/share/applications/otter.desktop
sudo install -Dm644 udev/99-samsung-odin.rules \
                 /etc/udev/rules.d/99-samsung-odin.rules

echo "==> reloading udev rules"
sudo udevadm control --reload-rules
sudo udevadm trigger

cat <<'MSG'

Done.  To run it:

    otter                       (or: ./otter from this directory)
    odin3-linux list            (driver only, no GUI)

Nothing needs root at flash time - the udev rule grants access to
Samsung (04e8) download-mode devices to your user.

First run:
    1. phone in Download mode, plug it in
    2. Refresh   -> the device appears
    3. Probe     -> identity + partition table (uses the entry's one session)
    4. power the phone off and re-enter Download mode
    5. pick BL/AP/CP/CSC/UMS files -> Start
MSG
