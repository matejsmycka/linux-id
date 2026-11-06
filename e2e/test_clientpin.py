"""CTAP PIN as the fallback to the fingerprint, against linux-id (memory backend).

usage: test_clientpin.py approve|deny|unavailable
  approve      daemon runs --auth e2e-approve (fingerprint always matches)
  deny         daemon runs --auth e2e-deny (fingerprint never matches)
  unavailable  daemon runs --auth e2e-unavailable (no usable sensor)
"""
import os, sys
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2
from fido2.ctap import CtapError
from fido2.cose import ES256

from fidodev import device

mode = sys.argv[1]
dev = device()
ctap = Ctap2(dev)
ok = lambda m: print("PASS", m)
P = ClientPin.PERMISSION
MCGA = P.MAKE_CREDENTIAL | P.GET_ASSERTION
alg = [{"type": "public-key", "alg": -7}]

def expect(code, f, *a, **kw):
    try:
        f(*a, **kw)
    except CtapError as e:
        assert e.code == code, f"got {e.code!r}, want {code!r}"
        return
    sys.exit(f"expected {code!r}, call succeeded")

def mc(rp, proto=None, tok=None, rk=True, uv=None):
    cdh = os.urandom(32)
    kw = {}
    if tok is not None:
        kw = dict(pin_uv_param=proto.authenticate(tok, cdh), pin_uv_protocol=proto.VERSION)
    opts = {"rk": rk}
    if uv is not None:
        opts["uv"] = uv
    return ctap.make_credential(cdh, {"id": rp}, {"id": os.urandom(8), "name": "u"}, alg, options=opts, **kw)

def ga(rp, proto=None, tok=None, uv=None):
    cdh = os.urandom(32)
    kw = {}
    if tok is not None:
        kw = dict(pin_uv_param=proto.authenticate(tok, cdh), pin_uv_protocol=proto.VERSION)
    return cdh, ctap.get_assertion(rp, cdh, options={"uv": True} if uv else None, **kw)

info = ctap.info
print("options", info.options, "minPINLength", info.min_pin_length, "forcePINChange", info.force_pin_change)
assert info.options.get("clientPin") is False and info.options.get("pinUvAuthToken")
assert info.options.get("makeCredUvNotRqd") is True and info.min_pin_length == 4
ok("GetInfo before setPIN: clientPin=false, minPINLength=4, makeCredUvNotRqd")

cp = ClientPin(ctap, PinProtocolV2())
expect(CtapError.ERR.PIN_NOT_SET, cp.get_pin_token, "1234", MCGA, "pin.example")
cp.set_pin("1234")
assert ctap.get_info().options.get("clientPin") is True
ok("setPIN; GetInfo clientPin=true")
expect(CtapError.ERR.PIN_AUTH_INVALID, cp.set_pin, "5678")
ok("second setPIN rejected (PIN_AUTH_INVALID)")
assert cp.get_pin_retries() == (8, False), cp.get_pin_retries()
ok("getPINRetries = 8, powerCycleState false")

if mode == "approve":
    for proto in (PinProtocolV2(), PinProtocolV1()):
        n = proto.VERSION
        c = ClientPin(ctap, proto)
        tok = c.get_pin_token("1234", MCGA, "pin.example")
        att = mc("pin.example", proto, tok)
        assert att.auth_data.flags & 0x05 == 0x05, hex(att.auth_data.flags)
        pub = ES256(att.auth_data.credential_data.public_key)
        cdh, a = ga("pin.example", proto, tok)
        pub.verify(a.auth_data + cdh, a.signature)
        assert a.auth_data.flags & 0x05 == 0x05, hex(a.auth_data.flags)
        ok(f"proto {n}: PIN token (mc|ga) -> makeCredential + getAssertion, UP|UV, signature verifies")
        legacy = c.get_pin_token("1234")  # legacy getPinToken: no permissions
        cdh, a = ga("pin.example", proto, legacy)
        assert a.auth_data.flags & 0x04
        ok(f"proto {n}: legacy getPinToken -> getAssertion UV")

    expect(CtapError.ERR.PIN_INVALID, cp.change_pin, "0000", "5678")
    assert cp.get_pin_retries()[0] == 7
    ok("changePIN with wrong PIN -> PIN_INVALID, retries 7")
    cp.change_pin("1234", "5678")
    assert cp.get_pin_retries() == (8, False)
    expect(CtapError.ERR.PIN_INVALID, cp.get_pin_token, "1234", MCGA, "pin.example")
    tok = cp.get_pin_token("5678", MCGA, "pin.example")
    ok("changePIN 1234 -> 5678; old PIN rejected, new PIN works, retries reset")

    expect(CtapError.ERR.PIN_INVALID, cp.get_pin_token, "0000", MCGA)
    expect(CtapError.ERR.PIN_INVALID, cp.get_pin_token, "0000", MCGA)
    print("retries after 3 wrong (incl. one above):", cp.get_pin_retries())
    expect(CtapError.ERR.PIN_AUTH_BLOCKED, cp.get_pin_token, "0000", MCGA)
    assert cp.get_pin_retries() == (5, True), cp.get_pin_retries()
    expect(CtapError.ERR.PIN_AUTH_BLOCKED, cp.get_pin_token, "5678", MCGA)
    ok("3 consecutive wrong PINs -> PIN_AUTH_BLOCKED, retries 5, powerCycleState true")

    # Built-in UV keeps working with a PIN set; and the PIN-set request rules.
    att = mc("uv.example", uv=True)
    assert att.auth_data.flags & 0x05 == 0x05
    ok("makeCredential uv=true (built-in UV) with PIN set -> UP|UV")
    expect(CtapError.ERR.PUAT_REQUIRED, mc, "rk.example")
    ok("discoverable makeCredential without uv/pinUvAuthParam -> PUAT_REQUIRED")
    att = mc("nonrk.example", rk=False)
    assert att.auth_data.flags & 0x05 == 0x01, hex(att.auth_data.flags)
    ok("non-discoverable makeCredential without uv (makeCredUvNotRqd) -> UP only")
    cdh, a = ga("uv.example")
    assert a.auth_data.flags & 0x05 == 0x01, hex(a.auth_data.flags)
    ok("getAssertion without uv -> UP only")
    expect(CtapError.ERR.PIN_INVALID, ctap.make_credential, os.urandom(32), {"id": "x.example"}, {"id": b"x"}, alg,
           pin_uv_param=b"", pin_uv_protocol=2)
    ok("zero-length pinUvAuthParam with PIN set -> PIN_INVALID")
    tok = ClientPin(ctap).get_uv_token(MCGA, "uv.example")
    ok("UV token still issued with PIN set")

elif mode == "deny":
    for i, want in enumerate((CtapError.ERR.UV_INVALID, CtapError.ERR.UV_INVALID, CtapError.ERR.UV_BLOCKED)):
        expect(want, cp.get_uv_token, MCGA, "fb.example")
        print("  uvRetries", cp.get_uv_retries())
    assert cp.get_uv_retries() == 0
    ok("fingerprint no-match x3 -> UV_INVALID, UV_INVALID, UV_BLOCKED; uvRetries 0")
    expect(CtapError.ERR.UV_BLOCKED, cp.get_uv_token, MCGA, "fb.example")
    expect(CtapError.ERR.PUAT_REQUIRED, mc, "fb.example", uv=True)
    ok("UV blocked: token -> UV_BLOCKED, uv=true makeCredential -> PUAT_REQUIRED")
    tok = cp.get_pin_token("1234", MCGA, "fb.example")
    assert cp.get_uv_retries() == 3
    ok("PIN token after UV_BLOCKED; uvRetries reset to 3")
    att = mc("fb.example", cp.protocol, tok)
    assert att.auth_data.flags & 0x05 == 0x05, hex(att.auth_data.flags)
    pub = ES256(att.auth_data.credential_data.public_key)
    cdh, a = ga("fb.example", cp.protocol, tok)
    pub.verify(a.auth_data + cdh, a.signature)
    assert a.auth_data.flags & 0x05 == 0x05
    ok("PIN token -> makeCredential + getAssertion (non-matching touch = presence), UP|UV")

elif mode == "unavailable":
    expect(CtapError.ERR.UV_BLOCKED, cp.get_uv_token, MCGA, "na.example")
    ok("fprintd unusable + PIN set -> UV_BLOCKED immediately")
    tok = cp.get_pin_token("1234", MCGA, "na.example")
    ok("PIN token issued")
    # No pinentry presence fallback in e2e builds: UP cannot be collected.
    expect(CtapError.ERR.OPERATION_DENIED, mc, "na.example", cp.protocol, tok)
    ok("without a presence fallback the request is denied (no silent UP)")

print("ALL PASS")
