"""authenticatorReset against the device run.sh started (fresh, so within its 10 s window)."""
import os, time
from fidodev import device
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin
from fido2.ctap import CtapError

ctap = Ctap2(device())
ok = lambda m: print("PASS", m)
alg = [{"type": "public-key", "alg": -7}]
cdh = os.urandom(32)

rk = ctap.make_credential(cdh, {"id": "reset.example"}, {"id": b"u", "name": "u"}, alg, options={"rk": True})
nrk = ctap.make_credential(cdh, {"id": "reset.example"}, {"id": b"v", "name": "v"}, alg)
ids = [rk.auth_data.credential_data.credential_id, nrk.auth_data.credential_data.credential_id]
ClientPin(ctap).set_pin("4711")
assert ctap.get_info().options["clientPin"]
ok("two credentials and a PIN before the reset")

ctap.reset()
ok("reset accepted within the window")

info = ctap.get_info()
assert not info.options["clientPin"], info.options; ok("PIN removed")
for cid in ids:
    try:
        ctap.get_assertion("reset.example", cdh, allow_list=[{"type": "public-key", "id": cid}])
        raise SystemExit("credential still signs after reset")
    except CtapError as e:
        assert e.code == CtapError.ERR.NO_CREDENTIALS, e
try:
    ctap.get_assertion("reset.example", cdh)
    raise SystemExit("discoverable credential survived reset")
except CtapError as e:
    assert e.code == CtapError.ERR.NO_CREDENTIALS, e
ok("old credentials (allowList and discoverable) refused")

new = ctap.make_credential(cdh, {"id": "reset.example"}, {"id": b"u", "name": "u"}, alg)
ctap.get_assertion("reset.example", cdh, allow_list=[{"type": "public-key", "id": new.auth_data.credential_data.credential_id}])
ok("new credential works after reset")

time.sleep(10.5)
try:
    ctap.reset()
    raise SystemExit("late reset accepted")
except CtapError as e:
    assert e.code == CtapError.ERR.NOT_ALLOWED, e
ok("reset refused after the 10 s window")
print("ALL PASS")
