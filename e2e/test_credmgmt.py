"""authenticatorCredentialManagement against linux-id (--auth e2e-approve, memory backend).

Needs $BIN (the linux-id binary run.sh started) for the CLI checks."""
import hashlib, json, os, subprocess, sys
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2
from fido2.ctap2.credman import CredentialManagement as CM
from fido2.ctap import CtapError
from fido2.cose import ES256
from fido2 import cbor

from fidodev import device
dev = device()
ctap = Ctap2(dev)
ok = lambda m: print("PASS", m)
info = ctap.info
print("options", info.options, "maxCredIdLength", info.max_cred_id_length)
assert info.options.get("credMgmt") and info.options.get("credentialMgmtPreview")
assert info.max_cred_id_length == 252  # TPM key handle (246) + credential ID header (6)
ok("getInfo advertises credMgmt, credentialMgmtPreview, maxCredentialIdLength")

P = ClientPin.PERMISSION
alg = [{"type": "public-key", "alg": -7}]
proto = PinProtocolV2()
cp = ClientPin(ctap, proto)

def make(rp, user, name):
    tok = cp.get_uv_token(P.MAKE_CREDENTIAL, rp)
    cdh = os.urandom(32)
    att = ctap.make_credential(cdh, {"id": rp, "name": rp.upper()}, {"id": user, "name": name, "displayName": name.title()},
                               alg, options={"rk": True}, pin_uv_param=proto.authenticate(tok, cdh), pin_uv_protocol=2)
    cd = att.auth_data.credential_data
    return cd.credential_id, cd.public_key

made = {}
for rp, user, name in [("a.example", b"ua1", "alice"), ("a.example", b"ua2", "bob"), ("b.example", b"ub1", "carol")]:
    made[name] = make(rp, user, name)

tok = cp.get_uv_token(P.CREDENTIAL_MGMT)
cm = CM(ctap, proto, tok)
md = cm.get_metadata()
assert md[CM.RESULT.EXISTING_CRED_COUNT] == 3, md
ok(f"getCredsMetadata: {md[CM.RESULT.EXISTING_CRED_COUNT]} existing, {md[CM.RESULT.MAX_REMAINING_COUNT]} remaining")

rps = cm.enumerate_rps()
assert sorted(r[CM.RESULT.RP]["id"] for r in rps) == ["a.example", "b.example"], rps
for r in rps:
    assert r[CM.RESULT.RP_ID_HASH] == hashlib.sha256(r[CM.RESULT.RP]["id"].encode()).digest()
ok("enumerateRPs: " + ", ".join(f'{r[CM.RESULT.RP]["id"]} ({r[CM.RESULT.RP].get("name")})' for r in rps))

creds = cm.enumerate_creds(hashlib.sha256(b"a.example").digest())
assert len(creds) == 2
for c in creds:
    name = c[CM.RESULT.USER]["name"]
    cid, pub = made[name]
    assert c[CM.RESULT.CREDENTIAL_ID]["id"] == cid and c[CM.RESULT.CREDENTIAL_ID]["type"] == "public-key"
    assert dict(c[CM.RESULT.PUBLIC_KEY]) == dict(pub), "publicKey differs from attested key"
    assert c[CM.RESULT.CRED_PROTECT] == 1 and c[CM.RESULT.USER]["displayName"] == name.title()
ok("enumerateCredentials a.example: users " + ", ".join(c[CM.RESULT.USER]["name"] for c in creds) + "; publicKey == attested key, credProtect 1")

# Proto 1 token works too.
cm1 = CM(ctap, PinProtocolV1(), ClientPin(ctap, PinProtocolV1()).get_uv_token(P.CREDENTIAL_MGMT))
assert len(cm1.enumerate_creds(hashlib.sha256(b"b.example").digest())) == 1; ok("protocol 1 token")
tok = cp.get_uv_token(P.CREDENTIAL_MGMT)  # the protocol 1 token replaced the first one
cm = CM(ctap, proto, tok)

# Preview alias 0x41.
msg = bytes([CM.CMD.ENUMERATE_RPS_BEGIN])
r = ctap.send_cbor(0x41, {1: CM.CMD.ENUMERATE_RPS_BEGIN, 3: 2, 4: proto.authenticate(tok, msg)})
assert r[CM.RESULT.TOTAL_RPS] == 2; ok("credentialMgmtPreview (0x41) enumerateRPsBegin")

# Iteration is ended by any other command.
cm.enumerate_rps_begin()
ctap.get_info()
try:
    cm.enumerate_rps_next(); sys.exit("getNextRP survived getInfo")
except CtapError as e:
    assert e.code == CtapError.ERR.NOT_ALLOWED, e; ok("getNextRP after getInfo -> NOT_ALLOWED")

# Update user information.
cid_bob = made["bob"][0]
cm.update_user_info({"type": "public-key", "id": cid_bob}, {"id": b"ua2", "name": "robert", "displayName": "Robert"})
names = sorted(c[CM.RESULT.USER]["name"] for c in cm.enumerate_creds(hashlib.sha256(b"a.example").digest()))
assert names == ["alice", "robert"], names; ok("updateUserInformation")
try:
    cm.update_user_info({"type": "public-key", "id": cid_bob}, {"id": b"other", "name": "x"}); sys.exit("user.id mismatch accepted")
except CtapError as e:
    assert e.code == CtapError.ERR.INVALID_PARAMETER, e; ok("update with another user.id -> INVALID_PARAMETER")

# Authorisation failures.
bad = CM(ctap, proto, os.urandom(32))
try:
    bad.get_metadata(); sys.exit("forged token accepted")
except CtapError as e:
    assert e.code == CtapError.ERR.PIN_AUTH_INVALID, e; ok("forged token -> PIN_AUTH_INVALID")
try:
    ctap.credential_mgmt(CM.CMD.GET_CREDS_METADATA); sys.exit("no pinUvAuthParam accepted")
except CtapError as e:
    assert e.code == CtapError.ERR.PUAT_REQUIRED, e; ok("no pinUvAuthParam -> PUAT_REQUIRED")
ga = CM(ctap, proto, cp.get_uv_token(P.GET_ASSERTION, "a.example"))
try:
    ga.get_metadata(); sys.exit("token without cm accepted")
except CtapError as e:
    assert e.code == CtapError.ERR.PIN_AUTH_INVALID, e; ok("token without cm permission -> PIN_AUTH_INVALID")
bound = CM(ctap, proto, cp.get_uv_token(P.CREDENTIAL_MGMT, "a.example"))
assert len(bound.enumerate_creds(hashlib.sha256(b"a.example").digest())) == 2
try:
    bound.enumerate_creds(hashlib.sha256(b"b.example").digest()); sys.exit("RP-bound token crossed RPs")
except CtapError as e:
    assert e.code == CtapError.ERR.PIN_AUTH_INVALID, e; ok("cm token bound to a.example: own RP ok, b.example -> PIN_AUTH_INVALID")

# Delete; the credential also stops working from an allowList.
tok = cp.get_uv_token(P.CREDENTIAL_MGMT)
cm = CM(ctap, proto, tok)
cid_alice = made["alice"][0]
cm.delete_cred({"type": "public-key", "id": cid_alice})
assert cm.get_metadata()[CM.RESULT.EXISTING_CRED_COUNT] == 2; ok("deleteCredential")
cdh = os.urandom(32)
try:
    ctap.get_assertion("a.example", cdh, allow_list=[{"type": "public-key", "id": cid_alice}]); sys.exit("deleted credential still signs")
except CtapError as e:
    assert e.code == CtapError.ERR.NO_CREDENTIALS, e; ok("deleted credential rejected in allowList -> NO_CREDENTIALS")
a = ctap.get_assertion("a.example", cdh, allow_list=[{"type": "public-key", "id": cid_bob}])
ES256(made["bob"][1]).verify(a.auth_data + cdh, a.signature); ok("remaining credential still signs")

# The CLI works on the same store while the daemon runs.
bin_, store = os.environ["BIN"], os.environ["LINUXID_CREDSTORE"]
cli = lambda *a, **kw: subprocess.run([bin_, "--credstore", store, "creds", *a], capture_output=True, text=True, **kw)
out = cli("list"); print(out.stdout, end=""); assert out.returncode == 0 and "robert" in out.stdout
j = json.loads(cli("list", "--json").stdout); assert {c["rpId"] for c in j} == {"a.example", "b.example"}
ok("CLI list / list --json")
out = cli("delete", "b.example", input="n\n"); assert out.returncode == 1 and "nothing deleted" in out.stdout
out = cli("delete", "-y", "b.example"); assert out.returncode == 0, out.stderr; print(out.stdout, end="")
assert [r[CM.RESULT.RP]["id"] for r in cm.enumerate_rps()] == ["a.example"]
ok("CLI delete (declined, then -y) is seen by the device")
print("ALL PASS")
