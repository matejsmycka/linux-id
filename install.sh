#!/bin/bash

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

    if [ ! -f "$script_dir/$executable" ] && ! command -v go &>/dev/null; then
        echo "Need a prebuilt ./linux-id binary or 'go' to build one" >&2
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

function check_aur_install() {
    if command -v pacman &>/dev/null && pacman -Q linux-id &>/dev/null; then
        echo "linux-id is already installed via the AUR package." >&2
        echo "Use 'sudo pacman -R linux-id' first if you want to switch to install.sh." >&2
        exit 1
    fi
}

function migrate_old_install() {
    local old_autostart="/home/$USER/.config/autostart/linux-id.desktop"
    if [ -f "$old_autostart" ]; then
        echo "Removing old autostart entry: $old_autostart"
        rm -f "$old_autostart"
    fi

    local old_user_unit="/home/$USER/.config/systemd/user/linux-id.service"
    if [ -f "$old_user_unit" ]; then
        echo "Removing old user systemd unit: $old_user_unit"
        systemctl --user disable linux-id.service 2>/dev/null || true
        rm -f "$old_user_unit"
    fi

    if [ -f /usr/local/bin/linux-id ]; then
        echo "Removing old binary: /usr/local/bin/linux-id"
        sudo rm -f /usr/local/bin/linux-id
    fi

    if [ -f /etc/udev/rules.d/70-uhid.rules ]; then
        echo "Removing old udev rule: /etc/udev/rules.d/70-uhid.rules"
        sudo rm -f /etc/udev/rules.d/70-uhid.rules
    fi

    if [ -f /etc/modules-load.d/uhid.conf ]; then
        echo "Removing old modules-load entry: /etc/modules-load.d/uhid.conf"
        sudo rm -f /etc/modules-load.d/uhid.conf
    fi

    if id -nG "$USER" | grep -qw tss; then
        echo "Note: user is still in the 'tss' group from a previous install."
        echo "      The new udev rule no longer needs it; you may run:"
        echo "          sudo gpasswd -d $USER tss"
    fi

    if pgrep -x linux-id >/dev/null; then
        echo "Stopping existing linux-id process"
        pkill -x linux-id || true
    fi
}

function make_executable() {
    if [ -f "$script_dir/$executable" ]; then
        echo "Using existing binary: $script_dir/$executable"
    else
        ( cd "$script_dir" && go build -o "$executable" )
        handle "Failed to build executable with go"
    fi

    sudo install -Dm755 "$script_dir/$executable" /usr/bin/"$executable"
    handle "Failed to install executable to /usr/bin"
}

function install_unit_and_rules() {
    sudo install -Dm644 /dev/stdin /usr/lib/systemd/user/linux-id.service <<'EOF'
[Unit]
Description=linux-id TPM service
Documentation=https://github.com/matejsmycka/linux-id
Wants=modprobe@uhid.service
After=modprobe@uhid.service
ConditionSecurity=tpm2
ConditionKernelModuleLoaded=uhid

[Service]
Type=simple
ExecStart=/usr/bin/linux-id

ProtectProc=noaccess
# pinentry may need to access /run/user/$UID/wayland-0
BindReadOnlyPaths=%t
# pinentry may need to access /tmp/.X11-unix
BindReadOnlyPaths=%T/.X11-unix
# pinentry may need to write here
BindPaths=%E
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=tmpfs
PrivateTmp=true
PrivateNetwork=true
PrivatePIDs=true
PrivateUsers=true
ProtectHostname=true
ProtectClock=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
# pinentry may need to connect to wayland/x11 socket
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
PrivateMounts=true

DeviceAllow=/dev/tpmrm0
DeviceAllow=/dev/uhid

[Install]
WantedBy=default.target
EOF
    handle "Failed to install systemd unit"

    sudo install -Dm644 /dev/stdin /usr/lib/udev/rules.d/60-linux-id-fido-tpm.rules <<'EOF'
# Allow user access tpmrm0 and uhid

KERNEL=="uhid",   SUBSYSTEM=="misc",  TAG+="uaccess"
KERNEL=="tpmrm0", SUBSYSTEM=="tpmrm", TAG+="uaccess"
EOF
    handle "Failed to install udev rules"

    sudo udevadm control --reload-rules
    sudo udevadm trigger --subsystem-match=misc --subsystem-match=tpmrm
}

function enable_user_service() {
    if ! systemctl --user daemon-reload 2>/dev/null; then
        echo
        echo "WARNING: could not reach your user systemd instance from this shell." >&2
        echo "Log back in to your desktop session, then run:" >&2
        echo "    systemctl --user daemon-reload" >&2
        echo "    systemctl --user enable --now linux-id.service" >&2
        echo "    systemctl --user status linux-id.service" >&2
        return
    fi

    systemctl --user enable linux-id.service
    handle "Failed to enable linux-id.service"

    if ! systemctl --user restart linux-id.service; then
        echo "WARNING: linux-id.service did not start cleanly. See status below." >&2
    fi

    echo
    echo "linux-id.service status:"
    echo "------------------------"
    systemctl --user --no-pager status linux-id.service || true
}

check_prereqs
check_aur_install
migrate_old_install
make_executable
install_unit_and_rules
enable_user_service

echo
echo "Installation successful. Log out and back in (or reboot) so the new"
echo "udev rules and user systemd unit are picked up."
