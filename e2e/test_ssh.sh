#!/bin/bash
# OpenSSH security keys against the device run.sh started: a resident
# ecdsa-sk key with verify-required, a signature, and ssh-keygen -K. Every
# ssh-keygen that talks to an authenticator runs in a bubblewrap sandbox whose
# /dev holds only $DEV, so it can never reach a real linux-id.
#   run.sh <binary> "e2e/test_ssh.sh"
set -u
here=$(cd "$(dirname "$0")" && pwd)
K=$(mktemp -d); trap 'rm -rf "$K"' EXIT
sandbox=(bwrap --dev-bind / / --dev /dev --dev-bind "$DEV" "$DEV" --)
pin=4711
printf '#!/bin/sh\necho %s\n' "$pin" > "$K/askpass"; chmod +x "$K/askpass"
export SSH_ASKPASS=$K/askpass SSH_ASKPASS_REQUIRE=force DISPLAY=none
fail() { echo "FAIL $*"; exit 1; }

"$here/.venv/bin/python" "$here/setpin.py" "$here" "$pin" || fail "set PIN"
"${sandbox[@]}" ssh-keygen -q -t ecdsa-sk -O resident -O verify-required -O application=ssh:lid-test \
  -O device="$DEV" -N '' -C resident-test -f "$K/id_rk" </dev/null || fail "create resident key"
echo "PASS resident ecdsa-sk key with verify-required"

echo hello > "$K/msg"
"${sandbox[@]}" ssh-keygen -Y sign -f "$K/id_rk" -n file "$K/msg" </dev/null >/dev/null 2>&1 || fail "sign"
echo "resident-test $(cut -d' ' -f1-2 "$K/id_rk.pub")" > "$K/allowed"
ssh-keygen -Y verify -f "$K/allowed" -I resident-test -n file -s "$K/msg.sig" < "$K/msg" >/dev/null || fail "verify"
echo "PASS signature verifies"

mkdir "$K/dl"
(cd "$K/dl" && "${sandbox[@]}" ssh-keygen -K </dev/null >/dev/null 2>&1) || fail "ssh-keygen -K"
cmp -s <(cut -d' ' -f1-2 "$K/id_rk.pub") <(cut -d' ' -f1-2 "$K/dl/id_ecdsa_sk_rk_lid-test.pub") || fail "downloaded key differs"
echo "PASS ssh-keygen -K downloads the same key"
echo "ALL PASS"
