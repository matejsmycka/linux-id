"""pinUvAuthToken via built-in UV, against linux-id (--auth e2e-approve, memory backend)."""
import os, sys
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2
from fido2.ctap import CtapError
from fido2.cose import ES256

from fidodev import device
dev = device()
ctap = Ctap2(dev)
ok = lambda m: print("PASS", m)
print("options", ctap.info.options, "pin protocols", ctap.info.pin_uv_protocols)
assert ctap.info.options.get("pinUvAuthToken") and ctap.info.pin_uv_protocols == [2, 1]

alg = [{"type": "public-key", "alg": -7}]
for proto in (PinProtocolV2(), PinProtocolV1()):
    n = proto.VERSION
    cp = ClientPin(ctap, proto)
    tok = cp.get_uv_token(ClientPin.PERMISSION.MAKE_CREDENTIAL | ClientPin.PERMISSION.GET_ASSERTION, "pin.example")
    cdh = os.urandom(32)
    att = ctap.make_credential(cdh, {"id": "pin.example"}, {"id": b"u%d" % n, "name": "u"}, alg,
                               options={"rk": True}, pin_uv_param=proto.authenticate(tok, cdh), pin_uv_protocol=n)
    assert att.auth_data.flags & 0x05 == 0x05, hex(att.auth_data.flags)
    ok(f"proto {n}: UV token -> makeCredential (UP|UV)")
    pub = ES256(att.auth_data.credential_data.public_key)
    cdh2 = os.urandom(32)
    a = ctap.get_assertion("pin.example", cdh2, pin_uv_param=proto.authenticate(tok, cdh2), pin_uv_protocol=n)
    pub.verify(a.auth_data + cdh2, a.signature)
    assert a.auth_data.flags & 0x04, "UV from token"
    ok(f"proto {n}: same token -> getAssertion, signature verifies, UV={bool(a.auth_data.flags & 4)} UP={bool(a.auth_data.flags & 1)}")
    try:
        ctap.get_assertion("other.example", cdh2, pin_uv_param=proto.authenticate(tok, cdh2), pin_uv_protocol=n)
        sys.exit("token used for another RP")
    except CtapError as e:
        assert e.code == CtapError.ERR.PIN_AUTH_INVALID, e; ok(f"proto {n}: token bound to RP")
    try:
        ctap.get_assertion("pin.example", cdh2, pin_uv_param=os.urandom(len(proto.authenticate(tok, cdh2))), pin_uv_protocol=n)
        sys.exit("forged param accepted")
    except CtapError as e:
        assert e.code == CtapError.ERR.PIN_AUTH_INVALID; ok(f"proto {n}: forged pinUvAuthParam rejected")

try:
    ctap.make_credential(os.urandom(32), {"id": "x.example"}, {"id": b"x"}, alg, pin_uv_param=b"", pin_uv_protocol=2)
    sys.exit("zero-length param accepted")
except CtapError as e:
    assert e.code == CtapError.ERR.PIN_NOT_SET, e; ok("zero-length pinUvAuthParam -> touch then PIN_NOT_SET")
try:
    ClientPin(ctap).get_uv_token(0x08)  # bio enrollment: unsupported
    sys.exit("unsupported permission granted")
except CtapError as e:
    assert e.code == CtapError.ERR.UNAUTHORIZED_PERMISSION; ok("unsupported permission rejected")
print("uv retries", ClientPin(ctap).get_uv_retries())
print("ALL PASS")
