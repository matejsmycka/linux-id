# Linux-id

Linux-id is FIDO token implementation for Linux that protects the token keys by using your system's TPM. linux-id uses Linux's [uhid](https://github.com/psanford/uhid) facility to emulate a USB HID device so that it is properly detected by browsers.

## Setup


```bash
curl -O https://raw.githubusercontent.com/matejsmycka/linux-id/refs/heads/main/install.sh
chmod +x install.sh
# Read what the script does before running it
./install.sh
```

If you are living on the edge, you can also run:
```bash
curl https://raw.githubusercontent.com/matejsmycka/linux-id/refs/heads/main/install.sh | bash
```

### Non-official

#### AUR

If you're using an Arch-based system, you can install linux-id from the AUR.
```bash
yay -Syy linux-id
```

[https://aur.archlinux.org/packages/linux-id](https://aur.archlinux.org/packages/linux-id)


## Test

You can test the installation by visiting [https://demo.yubico.com/webauthn-technical/registration](https://demo.yubico.com/webauthn-technical/registration) and follow fido token enroll and authentication steps.

## TPM-FIDO

This project is a fork of Psanford's [tpm-fido](https://github.com/psanford/tpm-fido) project.
However, after a discussion with the author, I have decided to create a new repository to better reflect the changes I have made.

### Differences

- This project aims to be more accessible to average users.
- I have updated old methods according to the latest Go standards.
- Old dependencies (e.g. pinetry) were replaced with updated ones.
- UX improvements.
- CTAP2 (biometric) support.

## CTAP2 / Passkeys

linux-id supports CTAP2 in addition to CTAP1/U2F, enabling passkey registration and authentication.

Use `--auth fprintd` for fingerprint authentication (sets UV flag, required by some sites); the default `pinentry` mode shows a click dialog but does not set UV.

To use fingerprint authentication, run:

```bash
./linux-id --auth fprintd
```

`fprintd` must be installed and your fingerprint enrolled via `fprintd-enroll`.

### Resident credentials

When a site requests `rk=true` (resident key), linux-id stores the credential locally at `~/.config/linux-id/creds.json`.

## Future work

- [ ] Add to linux distro package managers

##  Implementation details

linux-id uses the TPM 2.0 API. The overall design is as follows:

On registration linux-id generates a new P256 primary key under the Owner hierarchy on the TPM. To ensure that the key is unique per site and registration, linux-id generates a random 20 byte seed for each registration. The primary key template is populated with unique values from a sha256 hkdf of the 20 byte random seed and the application parameter provided by the browser.

A signing child key is then generated from that primary key. The key handle returned to the caller is a concatenation of the child key's public and private key handles and the 20 byte seed.

On an authentication request, linux-id will attempt to load the primary key by initializing the hkdf in the same manner as above. It will then attempt to load the child key from the provided key handle. Any incorrect values or values created by a different TPM will fail to load.

## Dependencies

linux-id requires `pinentry` to be available on the system. If you have gpg installed you most likely already have `pinentry`.

For fingerprint authentication (`--auth fprintd`), `fprintd` must be installed and running.

## Pinentry configuration

By default, linux-id tries to find an appropriate pinentry GUI client by checking for various common pinentry implementations. If you encounter issues with pinentry dialogs not appearing or the automatically selected pinentry doesn't work well in your environment, you can specify a specific pinentry binary using the `PINENTRY_PATH` environment variable:

```bash
# Set a specific pinentry program
PINENTRY_PATH=/usr/bin/pinentry-qt5 ./linux-id
```

You can typically find installed pinentry programs by running `ls /usr/bin/pinentry*`.

## Contributing

Please feel free to open an issue or PR if you have any suggestions or improvements.

