#!/bin/bash

executable=linux-id

function handle() {
    if [ $? -ne 0 ]; then
        echo "$1"
        exit 1
    fi
}

function make_executable() {
    go build -o $executable
    handle "Failed to build executable"
    chmod +x $executable
    handle "Failed to make executable"
    sudo cp $executable /usr/local/bin
    handle "Failed to copy executable"
    $executable -h
    handle "Failed to run executable"
}

function autostart() {
    if [ ! -d /etc/systemd ]; then
        echo "systemd is not present, exiting"
        exit 1
    fi

    cat <<EOF >>/home/$USER/.config/autostart/tpm-fido.desktop
[Desktop Entry]
Exec=/usr/local/bin/tpm-fido
Icon=
Name=tpm-fido
Path=
Terminal=False
Type=Application
EOF
    handle "Failed to add uhid to udev rules"
}

function check_prereqs() {
    if [ ! -d /sys/class/tpm/tpm0 ]; then
        echo "TPM is not present, make sure to enable it in BIOS/UEFI"
        exit 1
    fi

    if ! command -v go &>/dev/null; then
        echo "Go is not installed, please install it"
        exit 1
    fi

    if ! command -v pinentry &>/dev/null; then
        echo "Pinentry is not installed, please install it"
        exit 1
    fi

}

check_prereqs

if [ ! -f /usr/local/bin/$executable ]; then
    make_executable
else
    echo "Executable already exists, skipping"
fi

sudo usermod -aG tss $USER

handle "Failed to add user to tss group"

echo uhid | sudo tee /etc/modules-load.d/uhid.conf

handle "Failed to add uhid to modules"

echo 'KERNEL=="uhid", SUBSYSTEM=="misc", GROUP="users", MODE="0660"' | sudo tee /etc/udev/rules.d/70-uhid.rules

autostart

echo "Installation successful, now reboot"
