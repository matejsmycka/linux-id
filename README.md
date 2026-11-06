# Linux-id

Linux-id is FIDO token implementation for Linux that protects the token keys by using your system's TPM. linux-id uses Linux's [uhid](https://github.com/psanford/uhid) facility to emulate a USB HID device so that it is properly detected by browsers.

## Setup


```bash
curl -O https://raw.githubusercontent.com/matejsmycka/linux-id/refs/heads/main/install.sh
chmod +x install.sh
# Read what the script does before running it
./install.sh
```

To use fingerprint authentication, install with `--auth fprintd`.

```bash
./install.sh --auth fprintd
```

### Non-official

#### AUR

If you're using an Arch-based system, you can install linux-id from the AUR.
```bash
yay -Syy linux-id
```

[https://aur.archlinux.org/packages/linux-id](https://aur.archlinux.org/packages/linux-id)

#### Fedora

[![Copr build status](https://copr.fedorainfracloud.org/coprs/hamishw96/linux-id/package/linux-id/status_image/last_build.png)](https://copr.fedorainfracloud.org/coprs/hamishw96/linux-id/package/linux-id/)

On Fedora systems, you can use COPR to install linux-id:
``` bash
sudo dnf copr enable hamishw96/linux-id
sudo dnf install linux-id
```
By default, linux-id uses pinentry for presence confirmation. To use fingerprint
authentication via fprintd instead:

1. Ensure a fingerprint is enrolled: `fprintd-enroll`
2. Override the systemd service command: `systemctl --user edit linux-id.service`
3. Add the following lines:
```
[Service]
ExecStart=
ExecStart=/usr/bin/linux-id --auth fprintd
```
4. Restart the service: `systemctl --user restart linux-id.service`

https://copr.fedorainfracloud.org/coprs/hamishw96/linux-id/


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

linux-id implements CTAP 2.1: pinUvAuthToken (PIN/UV auth protocols 1 and 2), authenticatorCredentialManagement, authenticatorSelection, authenticatorReset, and the `credProtect`, `hmac-secret` (WebAuthn PRF) and `hmac-secret-mc` extensions. It sends CTAPHID keepalives while waiting for you and stops waiting when the browser cancels.

### PIN

The fingerprint is the everyday check; a CTAP PIN is the fallback when the finger is not recognised or the sensor is unavailable. Chrome's passkey management (Settings → Privacy and security → Security → Manage security keys) also requires one. Set it there, in Firefox's `about:webauthn`, or with `fido2-token -S <device>`.

The PIN is a TPM object: a sealed object whose authorisation value is the PIN hash the browser sends. Checking a PIN means asking the TPM to unseal it, so the TPM's dictionary attack protection limits guesses, and nothing on disk lets anyone test a guess without the TPM. linux-id blocks the PIN after 8 wrong tries; the TPM's own lockout counter is shared with every other DA-protected TPM object on the machine.

### Passkeys (resident credentials)

Discoverable credentials are listed in `~/.config/linux-id/creds.json` (or the file given with `--credstore`): the credential ID, which wraps the TPM-protected private key, plus the site, user handle, name, display name and public key. Manage them from the browser, with `fido2-token -L -r <device>`, or locally:

```bash
linux-id creds list
linux-id creds delete <id-prefix | rp-id>
```

A deleted credential also stops signing where a site still holds its ID.

### Reset

`linux-id reset`, or the browser's "reset security key" (within 10 seconds of linux-id starting: restart the service when the browser asks you to re-insert the key, then touch the sensor), retires every credential linux-id ever created, empties the passkey list and removes the PIN.

Credential keys are bound to a credential generation: a TPM monotonic NV counter (index `0x013C1D01`) whose secret is derived inside the TPM each time it is needed. A reset increments the counter, so it cannot be undone. Credentials created by earlier linux-id versions keep working after upgrading, until the first reset retires them (recorded in NV index `0x013C1D02`).

### ssh

OpenSSH security keys work, including resident keys: `ssh-keygen -t ecdsa-sk -O resident -O verify-required`, and `ssh-keygen -K` to download them.

### Options

- `--auth fprintd|pinentry`: how the user is verified.
- `--notify`: with fprintd, also show a desktop notification naming the site. Browsers show their own prompt, so it is off by default; it helps clients such as ssh.
- `--credstore FILE`: where discoverable credentials and the PIN state are kept.

### Tests

`go test ./...` runs the unit tests; `LINUXID_TPM_TEST=1` adds tests against `/dev/tpmrm0` (they use their own NV indices and remove them). [`e2e/`](e2e/README.md) drives a throwaway instance over the real uhid transport with python-fido2 and OpenSSH.

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

