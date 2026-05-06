#!/bin/bash

set -o pipefail

executable=linux-id
release_url="https://github.com/matejsmycka/linux-id/releases/latest/download/linux-id_Linux_x86_64.tar.gz"
script_dir="$(cd "$(dirname "$0")" && pwd)"

auth_mode="pinentry"

function usage() {
    cat <<EOF
Usage: $0 [--auth pinentry|fprintd] [-h|--help]

Options:
  --auth pinentry   Confirm presence with a click dialog (default).
  --auth fprintd    Confirm presence with a fingerprint scan.
                    Requires fprintd installed and a fingerprint enrolled
                    via 'fprintd-enroll'. Sets the WebAuthn UV flag.
  -h, --help        Show this help.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --auth)
            auth_mode="$2"
            shift 2
            ;;
        --auth=*)
            auth_mode="${1#--auth=}"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

case "$auth_mode" in
    pinentry|fprintd) ;;
    *)
        echo "Invalid --auth value: $auth_mode (must be 'pinentry' or 'fprintd')" >&2
        exit 1
        ;;
esac

if [ "$auth_mode" = "fprintd" ]; then
    auth_arg=" --auth fprintd"
else
    auth_arg=""
fi

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

    # Either we're in a source clone (go.mod + go) and build, or we download
    # the latest release tarball with curl/wget. No stale local binary path,
    # so re-running install.sh always picks up the latest published version.
    if [ -f "$script_dir/go.mod" ] && command -v go &>/dev/null; then
        :
    elif command -v curl &>/dev/null || command -v wget &>/dev/null; then
        :
    else
        echo "Need (go.mod + go) to build, or curl/wget to download the binary" >&2
        exit 1
    fi

    if ! command -v pinentry &>/dev/null; then
        echo "pinentry is not installed, please install it" >&2
        exit 1
    fi

    if [ "$auth_mode" = "fprintd" ] && ! command -v fprintd-enroll &>/dev/null; then
        echo "--auth fprintd requested but fprintd is not installed" >&2
        echo "Install fprintd first, then run 'fprintd-enroll' to enroll a finger" >&2
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
    local source_binary

    if [ -f "$script_dir/go.mod" ] && command -v go &>/dev/null; then
        echo "Building $executable from source in $script_dir"
        ( cd "$script_dir" && go build -o "$executable" )
        handle "Failed to build executable with go"
        source_binary="$script_dir/$executable"
    else
        local tmp
        tmp="$(mktemp -d)"
        trap 'rm -rf "$tmp"' EXIT
        echo "Downloading latest binary from $release_url"
        if command -v curl &>/dev/null; then
            curl -fsSL "$release_url" | tar -xz -C "$tmp"
        else
            wget -qO- "$release_url" | tar -xz -C "$tmp"
        fi
        handle "Failed to download or extract the prebuilt binary"
        if [ ! -f "$tmp/$executable" ]; then
            echo "Tarball did not contain '$executable':" >&2
            ls -la "$tmp" >&2
            exit 1
        fi
        source_binary="$tmp/$executable"
    fi

    sudo install -Dm755 "$source_binary" /usr/bin/"$executable"
    handle "Failed to install executable to /usr/bin"
}

function install_unit_and_rules() {
    sudo install -Dm644 /dev/stdin /usr/lib/systemd/user/linux-id.service <<EOF
[Unit]
Description=linux-id TPM service
Documentation=https://github.com/matejsmycka/linux-id
ConditionSecurity=tpm2
ConditionKernelModuleLoaded=uhid

[Service]
Type=simple
ExecStart=/usr/bin/linux-id${auth_arg}

ProtectProc=noaccess
# pinentry may need to access /run/user/\$UID/wayland-0
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

    sudo install -Dm644 /dev/stdin /usr/lib/modules-load.d/uhid.conf <<'EOF'
uhid
EOF
    handle "Failed to install modules-load entry"

    sudo udevadm control --reload-rules
    sudo udevadm trigger --subsystem-match=misc --subsystem-match=tpmrm

    if ! lsmod | grep -qw uhid; then
        sudo modprobe uhid
        handle "Failed to load uhid kernel module"
    fi
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

echo "Installing linux-id (auth=$auth_mode)"

check_prereqs
check_aur_install
migrate_old_install
make_executable
install_unit_and_rules
enable_user_service

echo
echo "Installation successful (auth=$auth_mode). Log out and back in (or reboot)"
echo "so the new udev rules and user systemd unit are picked up."
