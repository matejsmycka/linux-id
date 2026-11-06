# End-to-end tests

The scripts drive a throwaway linux-id over the real uhid transport with
[python-fido2](https://github.com/Yubico/python-fido2). They never touch a
running linux-id service or its credential store.

    python3 -m venv e2e/.venv
    e2e/.venv/bin/pip install -r e2e/requirements.txt
    go build -tags e2etest -o /tmp/linux-id-e2e .
    e2e/run.sh /tmp/linux-id-e2e "cd e2e && .venv/bin/python test_resident.py"

`run.sh` starts `--backend memory --auth e2e-approve` with a temporary
credential store, finds the hidraw node that instance created, exports it as
`DEV` and holds a lock so concurrent runs never see each other's devices.
Scripts open the device only through `fidodev.device()`.

| Script | Needs |
| --- | --- |
| `test_resident.py` | |
| `test_pinuv.py` | |
| `test_extensions.py` | |
| `test_credmgmt.py` | `BIN=<binary>` (exercises the `creds` CLI) |
| `test_clientpin.py approve` | |
| `test_clientpin.py deny` | `LINUXID_FLAGS="--auth e2e-deny"` |
| `test_clientpin.py unavailable` | `LINUXID_FLAGS="--auth e2e-unavailable"` |
| `test_reset.py` | a fresh instance (reset is only accepted within 10 s of start) |
| `test_ssh.sh` | `bwrap`, OpenSSH; run as `run.sh <bin> e2e/test_ssh.sh` |
