#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Otter one-line installer.
#
#   curl -fsSL https://raw.githubusercontent.com/leon1006965/Otter/main/setup.sh | sh
#
# Detects the distribution, installs build + GUI dependencies with the native
# package manager, builds the driver, installs `otter` and `odin3-linux` onto
# PATH, grants non-root access to Samsung download-mode devices, and prints
# how to launch it.
#
# POSIX sh - no bashisms, so it runs on Debian/Ubuntu, Fedora/RHEL, Arch,
# openSUSE and Alpine alike.

set -eu

REPO="leon1006965/Otter"
REPO_URL="https://github.com/${REPO}.git"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/main"
SRC_DIR="${OTTER_SRC:-${XDG_CACHE_HOME:-$HOME/.cache}/otter-src}"

say()  { printf '\033[1m => %s\033[0m\n' "$*"; }
ok()   { printf '      %s\n' "$*"; }
warn() { printf '\033[33m    ! %s\033[0m\n' "$*"; }
die()  { printf '\033[31merror: %s\033[0m\n' "$*" >&2; exit 1; }

printf '\n\033[1mOtter installer\033[0m\n\n'

# ---------------------------------------------------------------- privileges
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
else
    SUDO=""
    warn "no sudo available - installing to ~/.local/bin instead of /usr/local/bin"
fi

# ------------------------------------------------------------ package manager
detect_pm() {
    for pm in apt-get dnf yum pacman zypper apk; do
        if command -v "$pm" >/dev/null 2>&1; then echo "$pm"; return; fi
    done
    echo "unknown"
}
PM=$(detect_pm)
say "package manager: $PM"
[ "$PM" = "unknown" ] && warn "unrecognised system - you may need to install dependencies by hand"

# Are the pieces we need already here?  Skip the package manager entirely if so.
have_build()   { command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1; }
have_make()    { command -v make >/dev/null 2>&1; }
have_headers() { [ -e /usr/include/libusb-1.0/libusb.h ] || \
                 pkg-config --exists libusb-1.0 2>/dev/null; }
have_gui()     { command -v python3 >/dev/null 2>&1 && \
                 python3 -c 'import gi; gi.require_version("Gtk","3.0")' >/dev/null 2>&1; }

missing=""
have_build   || missing="$missing build"
have_make    || missing="$missing make"
have_headers || missing="$missing libusb"
have_gui     || missing="$missing gui"

if [ -z "$missing" ]; then
    ok "compiler, make, libusb headers and GTK bindings all present - skipping packages"
else
    say "missing:$missing - installing with $PM"
    case "$PM" in
        apt-get)
            $SUDO apt-get update -qq || warn "apt-get update failed, trying anyway"
            $SUDO apt-get install -y --no-install-recommends \
                build-essential libusb-1.0-0-dev pkg-config \
                python3 python3-gi gir1.2-gtk-3.0 git ca-certificates ;;
        dnf)
            $SUDO dnf install -y \
                gcc make libusb1-devel pkgconf-pkg-config \
                python3 python3-gobject gtk3 git ca-certificates ;;
        yum)
            $SUDO yum install -y \
                gcc make libusb1-devel pkgconfig \
                python3 python3-gobject gtk3 git ca-certificates ;;
        pacman)
            $SUDO pacman -Sy --noconfirm --needed \
                base-devel libusb python python-gobject gtk3 git ca-certificates ;;
        zypper)
            $SUDO zypper --non-interactive install \
                gcc make libusb-1_0-devel pkg-config \
                python3 python3-gobject gtk3 git ca-certificates ;;
        apk)
            $SUDO apk add --no-cache \
                build-base libusb-dev pkgconf \
                python3 py3-gobject gtk+3.0 git ca-certificates ;;
        *)
            warn "cannot install dependencies automatically" ;;
    esac

    have_build   || die "no C compiler found - install one and re-run"
    have_headers || die "libusb-1.0 headers not found - install them and re-run"
    have_gui     || warn "GTK bindings still missing: the driver works, the Otter GUI will not"
fi

# ---------------------------------------------------------------- get source
if [ -f ./Makefile ] && [ -f ./otter ]; then
    say "using the current directory as the source"
    SRC_DIR=$(pwd)
else
    if command -v git >/dev/null 2>&1; then
        say "cloning ${REPO} to ${SRC_DIR}"
        rm -rf "$SRC_DIR"
        git clone --depth 1 "$REPO_URL" "$SRC_DIR" >&2
    else
        say "downloading a source archive to ${SRC_DIR}"
        command -v curl >/dev/null 2>&1 || die "neither git nor curl is available"
        rm -rf "$SRC_DIR"; mkdir -p "$SRC_DIR"
        curl -fsSL "https://github.com/${REPO}/archive/refs/heads/main.tar.gz" | \
            tar -xz -C "$SRC_DIR" --strip-components=1
    fi
fi
cd "$SRC_DIR"

# ------------------------------------------------------------------- build
say "building odin3-linux"
make clean >/dev/null 2>&1 || true
make
[ -x ./odin3-linux ] || die "build did not produce ./odin3-linux"
[ -x ./otter ] || { chmod +x ./otter; }

# ----------------------------------------------------------------- install
# OTTER_PREFIX installs into a directory you own (no password needed) and
# skips the system-wide udev rule, which is the one part that needs root.
CUSTOM_PREFIX=""
if [ -n "${OTTER_PREFIX:-}" ]; then
    BIN_DIR="$OTTER_PREFIX/bin"
    APP_DIR="$OTTER_PREFIX/share/applications"
    SUDO=""
    CUSTOM_PREFIX=1
elif [ -n "$SUDO" ] || [ "$(id -u)" -eq 0 ]; then
    BIN_DIR="/usr/local/bin"
    APP_DIR="/usr/local/share/applications"
else
    BIN_DIR="$HOME/.local/bin"
    APP_DIR="$HOME/.local/share/applications"
fi

say "installing to ${BIN_DIR}"
$SUDO mkdir -p "$BIN_DIR" "$APP_DIR"
$SUDO cp ./odin3-linux "$BIN_DIR/odin3-linux"
$SUDO cp ./otter       "$BIN_DIR/otter"
$SUDO chmod 0755 "$BIN_DIR/odin3-linux" "$BIN_DIR/otter"
$SUDO cp ./otter.desktop "$APP_DIR/otter.desktop" 2>/dev/null || true
ok "$BIN_DIR/otter"
ok "$BIN_DIR/odin3-linux"

# --------------------------------------------------------------- udev rules
say "granting access to Samsung download-mode devices"
if [ -n "$CUSTOM_PREFIX" ]; then
    warn "custom prefix: skipping the system udev rule"
    printf '      sudo cp %s/udev/99-samsung-odin.rules /etc/udev/rules.d/\n' "$SRC_DIR"
    printf '      sudo udevadm control --reload-rules && sudo udevadm trigger\n'
elif [ -d /etc/udev/rules.d ]; then
    if [ -n "$SUDO" ] || [ "$(id -u)" -eq 0 ]; then
        $SUDO cp ./udev/99-samsung-odin.rules /etc/udev/rules.d/99-samsung-odin.rules
        if command -v udevadm >/dev/null 2>&1; then
            $SUDO udevadm control --reload-rules 2>/dev/null || true
            $SUDO udevadm trigger 2>/dev/null || true
        fi
        ok "udev rule installed - no root needed when flashing"
    else
        warn "cannot write /etc/udev/rules.d - flashing will need root until you run:"
        printf '      sudo cp %s/udev/99-samsung-odin.rules /etc/udev/rules.d/\n' "$SRC_DIR"
    fi
else
    warn "no /etc/udev/rules.d on this system - flashing may need root"
fi

# ---------------------------------------------------------------------- PATH
case ":${PATH}:" in
    *":${BIN_DIR}:"*) ok "${BIN_DIR} is already on PATH" ;;
    *)
        say "adding ${BIN_DIR} to PATH"
        line="export PATH=\"${BIN_DIR}:\$PATH\""
        for rc in "$HOME/.profile" "$HOME/.bashrc" "$HOME/.zshrc"; do
            [ -e "$rc" ] || continue
            grep -Fq "${BIN_DIR}" "$rc" 2>/dev/null && continue
            printf '\n# Otter\n%s\n' "$line" >> "$rc"
            ok "updated $rc"
        done
        if [ ! -e "$HOME/.profile" ] && [ ! -e "$HOME/.bashrc" ] && [ ! -e "$HOME/.zshrc" ]; then
            printf '\n# Otter\n%s\n' "$line" > "$HOME/.profile"
            ok "created ~/.profile"
        fi
        warn "a NEW terminal is required for PATH to take effect"
        ;;
esac

# ------------------------------------------------------------------- summary
printf '\n\033[1m============================================================\033[0m\n'
printf '\033[1m Otter is installed.\033[0m\n\n'
printf ' Open a NEW terminal and type:\n\n'
printf '     \033[1motter\033[0m\n\n'
printf ' Driver only, no GUI:\n\n'
printf '     \033[1modin3-linux list\033[0m\n'
printf '\033[1m============================================================\033[0m\n\n'
printf ' First run: put the phone in Download mode, plug it in, then\n'
printf ' Refresh -> Probe -> power the phone off and re-enter Download\n'
printf ' mode -> pick files -> Start.\n\n'
