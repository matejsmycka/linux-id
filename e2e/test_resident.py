"""End-to-end CTAP2 checks against a running linux-id (--backend memory, test verifier)."""
import os, sys, hashlib
from fido2.hid import CtapHidDevice, CTAPHID
from fido2.ctap2 import Ctap2
from fido2.ctap import CtapError
from fido2.cose import ES256

def find():
    for d in CtapHidDevice.list_devices():
        if d.descriptor.vid == 0x15d9 and d.descriptor.pid == 0x0a37:
            return d
    sys.exit("linux-id device not found")

from fidodev import device
dev = device()
ok = lambda m: print("PASS", m)

# Transport
assert dev.call(CTAPHID.PING, b"x" * 300) == b"x" * 300; ok("ping 300 bytes")
dev.call(CTAPHID.WINK); ok("wink")

ctap = Ctap2(dev)
info = ctap.info
print("versions", info.versions, "options", info.options, "algs", info.algorithms, "transports", info.transports)
assert info.transports == ["usb"] and info.max_creds_in_list == 16; ok("getInfo fields")

cdh = os.urandom(32)
rp = {"id": "multi.example", "name": "Multi"}
alg = [{"type": "public-key", "alg": -7}]
keys = {}
for name in ["alice", "bob", "alice"]:
    att = ctap.make_credential(cdh, rp, {"id": name.encode(), "name": name, "displayName": name.title()}, alg, options={"rk": True})
    cd = att.auth_data.credential_data
    assert att.auth_data.rp_id_hash == hashlib.sha256(b"multi.example").digest()
    assert att.auth_data.flags & 0x45 == 0x45  # UP|UV|AT
    keys[cd.credential_id] = (name, ES256(cd.public_key))
ok("3x makeCredential rk (alice re-registered)")

res = ctap.get_assertions("multi.example", cdh)
print("assertions:", [(r.user["id"], r.user.get("name"), r.number_of_credentials) for r in res])
assert len(res) == 2, len(res)
assert [r.user["id"] for r in res] == [b"alice", b"bob"], "newest first, old alice replaced"
for r in res:
    name, pub = keys[r.credential["id"]]
    pub.verify(r.auth_data + cdh, r.signature)
    assert r.user["name"] == name
ok("getAssertion + getNextAssertion, signatures verify, old alice gone")

r = ctap.get_assertion("multi.example", cdh, options={"up": False})
assert r.auth_data.flags & 0x05 == 0 and "name" not in r.user; ok("silent up=false probe: no UP/UV, no PII")

try:
    ctap.get_assertion("nothing.example", cdh); raise SystemExit("expected NO_CREDENTIALS")
except CtapError as e:
    assert e.code == CtapError.ERR.NO_CREDENTIALS; ok("no credentials error")

try:
    ctap.send_cbor(0xBF); raise SystemExit("expected INVALID_COMMAND")
except CtapError as e:
    assert e.code == CtapError.ERR.INVALID_COMMAND; ok("unknown command")
print("ALL PASS")
