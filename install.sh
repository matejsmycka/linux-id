#!/bin/bash
#
# Manual installer for linux-id. Mirrors the AUR package layout
# (https://aur.archlinux.org/linux-id) so a system installed via this
# script and one installed via `pacman -S linux-id` produce the same
# runtime configuration:
#
#   /usr/bin/linux-id                                       (binary)
#   /usr/lib/systemd/user/linux-id.service                  (user unit)
#   /usr/lib/udev/rules.d/60-linux-id-fido-tpm.rules        (udev rules)
#
# The .service and .rules files shipped under contrib/ in this repo are
# byte-identical to the ones in the AUR package.

set -o pipefail

executable=linux-id
script_dir="$(cd "$(dirname "$0")" && pwd)"

function handle() {
    if [ $? -ne 0 ]; then
        echo "$1" >&2
        exit 1
    fi
}

function check_prereqs() {
    if [ ! -d /sys/class/tpm/tpm0 ]; then
        echo "TPM is not present, make sure to enable it in BIOS/UEFI" >&2
        exit 1
    fi

    if ! command -v go &>/dev/null \
        && ! command -v podman &>/dev/null \
        && ! command -v docker &>/dev/null; then
        echo "Need go, podman, or docker to build the binary" >&2
        exit 1
    fi

    if ! command -v pinentry &>/dev/null; then
        echo "pinentry is not installed, please install it" >&2
        exit 1
    fi

    if ! command -v systemctl &>/dev/null; then
        echo "systemctl not found — systemd is required" >&2
        exit 1
    fi
}

# Refuse to clobber an AUR install. Both methods produce the same files at the
# same paths, so a manual install on top of pacman-managed files would leave
# pacman's database out of sync with the filesystem.
function check_aur_install() {
    if command -v pacman &>/dev/null && pacman -Q linux-id &>/dev/null; then
        echo "linux-id is already installed via the AUR package." >&2
        echo "Use 'sudo pacman -R linux-id' first if you want to switch to install.sh." >&2
        exit 1
    fi
}

# Strip leftovers from previous install.sh versions before they shipped the
# AUR-aligned layout. Safe to run when nothing old exists.
function migrate_old_install() {
    # Old desktop autostart entry.
    local old_autostart="/home/$USER/.config/autostart/linux-id.desktop"
    if [ -f "$old_autostart" ]; then
        echo "Removing old autostart entry: $old_autostart"
        rm -f "$old_autostart"
    fi

    # Old per-user systemd unit (an intermediate revision of install.sh
    # installed it here before we moved to the AUR-mirrored location).
    local old_user_unit="/home/$USER/.config/systemd/user/linux-id.service"
    if [ -f "$old_user_unit" ]; then
        echo "Removing old user systemd unit: $old_user_unit"
        systemctl --user disable linux-id.service 2>/dev/null || true
        rm -f "$old_user_unit"
    fi

    # Old binary location.
    if [ -f /usr/local/bin/linux-id ]; then
        echo "Removing old binary: /usr/local/bin/linux-id"
        sudo rm -f /usr/local/bin/linux-id
    fi

    # Old udev rule. The AUR rules use TAG+="uaccess" instead of GROUP="users",
    # which is the modern systemd-logind way of granting device access to the
    # active local user — no group membership needed.
    if [ -f /etc/udev/rules.d/70-uhid.rules ]; then
        echo "Removing old udev rule: /etc/udev/rules.d/70-uhid.rules"
        sudo rm -f /etc/udev/rules.d/70-uhid.rules
    fi

    # Old modules-load.d entry. The AUR unit `Wants=modprobe@uhid.service`,
    # so we no longer need a separate modprobe-on-boot config.
    if [ -f /etc/modules-load.d/uhid.conf ]; then
        echo "Removing old modules-load entry: /etc/modules-load.d/uhid.conf"
        sudo rm -f /etc/modules-load.d/uhid.conf
    fi

    # Old user-in-tss-group setup. The new udev rule grants access via uaccess,
    # so the tss group is unnecessary. We do NOT remove the user from the group
    # automatically — that could break unrelated TPM tooling. Just print a hint.
    if id -nG "$USER" | grep -qw tss; then
        echo "Note: user is still in the 'tss' group from a previous install."
        echo "      The new udev rule no longer needs it; you may run:"
        echo "          sudo gpasswd -d $USER tss"
    fi

    # Stop any currently running instance from the previous install.
    if pgrep -x linux-id >/dev/null; then
        echo "Stopping existing linux-id process"
        pkill -x linux-id || true
    fi
}

function make_executable() {
    if command -v go &>/dev/null; then
        go build -o "$executable"
    elif command -v podman &>/dev/null; then
        podman run --rm -v "$PWD:/workdir:Z" -w "/workdir" golang:latest go build -o "$executable"
    else
        docker run --rm -v "$PWD:/workdir" -w "/workdir" golang:latest go build -o "$executable"
    fi
    handle "Failed to build executable"

    sudo install -Dm755 "$executable" /usr/bin/"$executable"
    handle "Failed to install executable to /usr/bin"
}

function install_unit_and_rules() {
    if [ ! -f "$script_dir/contrib/linux-id.service" ]; then
        echo "Missing contrib/linux-id.service in $script_dir" >&2
        exit 1
    fi
    if [ ! -f "$script_dir/contrib/linux-id.rules" ]; then
        echo "Missing contrib/linux-id.rules in $script_dir" >&2
        exit 1
    fi

    # Mirror the AUR package's install paths exactly, so the resulting
    # filesystem state is indistinguishable from a `pacman -S linux-id`.
    sudo install -Dm644 "$script_dir/contrib/linux-id.service" \
        /usr/lib/systemd/user/linux-id.service
    handle "Failed to install systemd unit"

    sudo install -Dm644 "$script_dir/contrib/linux-id.rules" \
        /usr/lib/udev/rules.d/60-linux-id-fido-tpm.rules
    handle "Failed to install udev rules"

    # Reload udev so the new uaccess tag applies without a reboot.
    sudo udevadm control --reload-rules
    sudo udevadm trigger --subsystem-match=misc --subsystem-match=tpmrm
}

function enable_user_service() {
    # All systemctl --user calls run as the unprivileged user against the user
    # systemd instance — no sudo. If install.sh is being executed from a TTY
    # without an active graphical session, the user bus may not be reachable;
    # fall back to printed instructions so the install still finishes cleanly.
    if ! systemctl --user daemon-reload 2>/dev/null; then
        echo
        echo "WARNING: could not reach your user systemd instance from this shell." >&2
        echo "Log back in to your desktop session, then run:" >&2
        echo "    systemctl --user daemon-reload" >&2
        echo "    systemctl --user enable --now linux-id.service" >&2
        echo "    systemctl --user status linux-id.service" >&2
        return
    fi

    # Enable so the unit autostarts on next login (default.target.wants).
    systemctl --user enable linux-id.service
    handle "Failed to enable linux-id.service"

    # restart starts a stopped unit and restarts a running one — works for
    # fresh installs and re-installs without branching. We tolerate non-zero
    # because some failure modes (e.g. ConditionSecurity=tpm2 not satisfied)
    # leave the unit inactive and we want to print status either way.
    if ! systemctl --user restart linux-id.service; then
        echo "WARNING: linux-id.service did not start cleanly. See status below." >&2
    fi

    echo
    echo "linux-id.service status:"
    echo "------------------------"
    systemctl --user --no-pager status linux-id.service || true
}

# ===== main =====
check_prereqs
check_aur_install
migrate_old_install
make_executable
install_unit_and_rules
enable_user_service

echo
echo "Installation successful. Log out and back in (or reboot) so the new"
echo "udev rules and user systemd unit are picked up."
