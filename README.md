# linux-id

linux-id is FIDO token implementation for Linux that protects the token keys by using your system's TPM. linux-id uses Linux's [uhid](https://github.com/psanford/uhid) facility to emulate a USB HID device so that it is properly detected by browsers.

## Setup

You can install linux-id by running the following commands:

```bash
git clone git@github.com:matejsmycka/linux-id.git
cd linux-id

go install

chmod +x install.sh
./install.sh
```

This will set up Linux-id persistently on your machine; note that this will autostart Linux-id on login.

Or you can skip compiling with the download of the latest release.

```bash
curl -L https://github.com/matejsmycka/linux-id/releases/download/v0.1.1/linux-id_Linux_x86_64.tar.gz | tar xz
chmod +x linux-id
```

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

## Future work

- [ ] Add support for fingerprint and PIN authentication
- [ ] Add to linux distro package managers

## Manual setup

In order to run `linux-id` you will need permission to access `/dev/tpmrm0`. On Ubuntu and Arch, you can add your user to the `tss` group.

Your user also needs permission to access `/dev/uhid` so that `linux-id` can appear to be a USB device.
I use the following udev rule to set the appropriate `uhid` permissions:

```
KERNEL=="uhid", SUBSYSTEM=="misc", GROUP="SOME_UHID_GROUP_MY_USER_BELONGS_TO", MODE="0660"
```

To ensure the above udev rule gets triggered, I also add the `uhid` module to `/etc/modules-load.d/uhid.conf` so that it loads at boot.

To run:

```
# as a user that has permission to read and write to /dev/tpmrm0:
./linux-id
```
Note: do not run with `sudo` or as root, as it will not work.


##  Implementation details

linux-id uses the TPM 2.0 API. The overall design is as follows:

On registration linux-id generates a new P256 primary key under the Owner hierarchy on the TPM. To ensure that the key is unique per site and registration, linux-id generates a random 20 byte seed for each registration. The primary key template is populated with unique values from a sha256 hkdf of the 20 byte random seed and the application parameter provided by the browser.

A signing child key is then generated from that primary key. The key handle returned to the caller is a concatenation of the child key's public and private key handles and the 20 byte seed.

On an authentication request, linux-id will attempt to load the primary key by initializing the hkdf in the same manner as above. It will then attempt to load the child key from the provided key handle. Any incorrect values or values created by a different TPM will fail to load.

## Dependencies

linux-id requires `pinentry` to be available on the system. If you have gpg installed you most likely already have `pinentry`.
You will need `go` with version 1.22 or higher (only for compiling).

## Known Issues

By default, linux-id tries to find an appropriate pinentry GUI client by checking for various common pinentry implementations. If you encounter issues with pinentry dialogs not appearing or the automatically selected pinentry doesn't work well in your environment, you can specify a specific pinentry binary using the `PINENTRY_PATH` environment variable:

```bash
# Set a specific pinentry program
PINENTRY_PATH=/usr/bin/pinentry-qt5 ./linux-id
```

You can typically find installed pinentry programs by running `ls /usr/bin/pinentry*`.

## Contributing

Please feel free to open an issue or PR if you have any suggestions or improvements.
