"""hmac-secret (+ -mc), WebAuthn prf and credProtect against linux-id
(--auth e2e-approve, memory backend). e2e-approve verifies the user on every
request that asks for one, so "no UV" below means a silent up=false request."""
import hashlib, os, sys
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2
from fido2.ctap2.extensions import HmacSecretExtension, CredProtectExtension
from fido2.ctap import CtapError
from fido2.cose import ES256
from fido2.client import Fido2Client, DefaultClientDataCollector
from fido2.webauthn import (PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
                            PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
                            PublicKeyCredentialParameters, PublicKeyCredentialDescriptor,
                            PublicKeyCredentialType, UserVerificationRequirement)

from fidodev import device
dev = device()
ctap = Ctap2(dev)
ok = lambda m: print("PASS", m)
ED, UV, UP = 0x80, 0x04, 0x01
alg = [{"type": "public-key", "alg": -7}]

print("extensions", ctap.info.extensions)
assert ctap.info.extensions == ["credProtect", "hmac-secret", "hmac-secret-mc"], ctap.info.extensions
assert ctap.info.versions == ["FIDO_2_0", "FIDO_2_1", "U2F_V2"], ctap.info.versions
ok("GetInfo advertises credProtect, hmac-secret, hmac-secret-mc")


def hmac_input(proto, *salts, tamper=False):
    key_agreement, shared = ClientPin(ctap, proto)._get_shared_secret()
    enc = proto.encrypt(shared, b"".join(salts))
    auth = proto.authenticate(shared, enc)
    if tamper:
        auth = bytes([auth[0] ^ 1]) + auth[1:]
    return {"hmac-secret": {1: key_agreement, 2: enc, 3: auth, 4: proto.VERSION}}, shared


def assertion(rp, cdh, allow=None, ext=None, up=True):
    return ctap.get_assertion(rp, cdh, allow_list=allow, extensions=ext,
                              options=None if up else {"up": False})


# --- hmac-secret through raw CTAP, both PIN/UV protocols -------------------
s1, s2 = os.urandom(32), os.urandom(32)
cdh = os.urandom(32)
att = ctap.make_credential(cdh, {"id": "hs.example"}, {"id": b"hs", "name": "hs"}, alg,
                           extensions={"hmac-secret": True})
assert att.auth_data.flags & ED and att.auth_data.extensions == {"hmac-secret": True}, att.auth_data
ok("makeCredential hmac-secret: true -> ED + {hmac-secret: true}")
pub = ES256(att.auth_data.credential_data.public_key)
allow = [{"type": "public-key", "id": att.auth_data.credential_data.credential_id}]

outs = {}
for proto in (PinProtocolV1(), PinProtocolV2()):
    n = proto.VERSION
    for salts in ((s1,), (s1, s2)):
        ext, shared = hmac_input(proto, *salts)
        a = assertion("hs.example", cdh, allow, ext)
        pub.verify(a.auth_data + cdh, a.signature)
        assert a.auth_data.flags & (ED | UV) == ED | UV, hex(a.auth_data.flags)
        out = proto.decrypt(shared, a.auth_data.extensions["hmac-secret"])
        assert len(out) == 32 * len(salts), len(out)
        outs[(n, len(salts))] = out
    assert outs[(n, 2)][:32] == outs[(n, 1)], "salt1 output differs between 1 and 2 salts"
    ok(f"proto {n}: one and two salts, signature over authData+extensions verifies")
assert outs[(1, 2)] == outs[(2, 2)], "output depends on the PIN/UV protocol"
ok("same outputs over protocol 1 and 2")

ext, shared = hmac_input(PinProtocolV2(), s1)
a = assertion("hs.example", cdh, allow, ext, up=False)
assert not a.auth_data.flags & UV
no_uv = PinProtocolV2().decrypt(shared, a.auth_data.extensions["hmac-secret"])
assert no_uv != outs[(2, 1)], "UV and non-UV CredRandom are the same"
ok("silent (non-UV) request uses the other CredRandom")

for proto in (PinProtocolV1(), PinProtocolV2()):
    ext, _ = hmac_input(proto, s1, tamper=True)
    try:
        assertion("hs.example", cdh, allow, ext)
        sys.exit("tampered saltAuth accepted")
    except CtapError as e:
        assert e.code == CtapError.ERR.PIN_AUTH_INVALID, e
ok("bad saltAuth -> PIN_AUTH_INVALID")
ext, _ = hmac_input(PinProtocolV2(), os.urandom(16))
try:
    assertion("hs.example", cdh, allow, ext)
    sys.exit("16-byte salt accepted")
except CtapError as e:
    assert e.code == CtapError.ERR.INVALID_LENGTH, e
ok("16-byte salt -> INVALID_LENGTH")

# --- credProtect ------------------------------------------------------------
for level in (1, 2, 3):
    att = ctap.make_credential(os.urandom(32), {"id": f"cp{level}.example"}, {"id": b"u", "name": "u"}, alg,
                               extensions={"credProtect": level}, options={"rk": True})
    assert att.auth_data.extensions == {"credProtect": level}, att.auth_data.extensions
    allow = [{"type": "public-key", "id": att.auth_data.credential_data.credential_id}]
    rp = f"cp{level}.example"
    results = {}
    for name, kw in {"discoverable, no UV": dict(up=False), "allowList, no UV": dict(allow=allow, up=False),
                     "discoverable, UV": dict(), "allowList, UV": dict(allow=allow)}.items():
        try:
            assertion(rp, os.urandom(32), **kw)
            results[name] = True
        except CtapError as e:
            assert e.code == CtapError.ERR.NO_CREDENTIALS, e
            results[name] = False
    want = {1: [True, True, True, True], 2: [False, True, True, True], 3: [False, False, True, True]}[level]
    assert list(results.values()) == want, (level, results)
    ok(f"credProtect {level}: echoed; usable {results}")

# --- WebAuthn prf through Fido2Client (hmac-secret-mc at create) -----------
client = Fido2Client(dev, DefaultClientDataCollector("https://prf.example"),
                     extensions=[HmacSecretExtension(), CredProtectExtension()])
first, second = b"first salt", b"second salt"
reg = client.make_credential(PublicKeyCredentialCreationOptions(
    rp=PublicKeyCredentialRpEntity(id="prf.example", name="PRF"),
    user=PublicKeyCredentialUserEntity(id=b"prf-user", name="prf"),
    challenge=os.urandom(32),
    pub_key_cred_params=[PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-7)],
    extensions={"prf": {"eval": {"first": first}},
                "credentialProtectionPolicy": "userVerificationRequired"},
))
reg_ext = dict(reg.client_extension_results)
print("registration extension results", reg_ext)
assert reg_ext["prf"]["enabled"] is True
mc_first = reg_ext["prf"]["results"]["first"]
cred_id = reg.raw_id
ok("prf enabled at registration, with results via hmac-secret-mc")


def prf_get():
    r = client.get_assertion(PublicKeyCredentialRequestOptions(
        challenge=os.urandom(32), rp_id="prf.example",
        allow_credentials=[PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY, id=cred_id)],
        user_verification=UserVerificationRequirement.REQUIRED,
        extensions={"prf": {"eval": {"first": first, "second": second}}},
    )).get_response(0)
    return dict(r.client_extension_results)["prf"]["results"]


r1, r2 = prf_get(), prf_get()
print("prf results", r1)
assert r1 == r2, "prf not stable"
assert r1["first"] == mc_first, "prf at create differs from prf at get"
assert r1["first"] != r1["second"]
# prf salts are SHA-256("WebAuthn PRF" || 0 || input); check against raw hmac-secret.
raw_salt = hashlib.sha256(b"WebAuthn PRF\x00" + first).digest()
ext, shared = hmac_input(PinProtocolV2(), raw_salt)
a = assertion("prf.example", os.urandom(32), [{"type": "public-key", "id": cred_id}], ext)
import base64
raw = PinProtocolV2().decrypt(shared, a.auth_data.extensions["hmac-secret"])
first_bytes = r1["first"] if isinstance(r1["first"], bytes) else base64.urlsafe_b64decode(r1["first"] + "==")
assert raw == first_bytes, "prf result is not hmac-secret over the PRF salt"
ok("prf: stable, matches hmac-secret-mc and raw hmac-secret")
print("ALL PASS")
