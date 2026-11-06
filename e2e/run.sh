#!/bin/bash
# usage: run.sh <linux-id binary built with -tags e2etest> <command...>
# Starts a throwaway linux-id (--backend memory --auth e2e-approve, temp
# credstore) on uhid, finds the hidraw node *it* created, exports DEV=<path>,
# and runs the command. Runs are serialised with a lock so concurrent
# callers never see each other's devices. Never touches the real service.
set -u
bin=$1; shift
exec 9>/tmp/linux-id-e2e.lock
flock 9
log=$(mktemp); store=$(mktemp -d)/creds.json
before=$(ls /dev/hidraw* 2>/dev/null | sort)
"$bin" --backend memory --auth e2e-approve --credstore "$store" ${LINUXID_FLAGS:-} >"$log" 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null; wait $pid 2>/dev/null; rm -rf "$(dirname "$store")" "$log"' EXIT
DEV=
for _ in $(seq 50); do
  for n in $(comm -13 <(echo "$before") <(ls /dev/hidraw* 2>/dev/null | sort)); do
    [ "$(cat /sys/class/hidraw/${n#/dev/}/device/uevent 2>/dev/null | grep -c 'HID_ID=0003:000015D9:00000A37')" = 1 ] && DEV=$n
  done
  [ -n "$DEV" ] && break
  sleep 0.1
done
[ -z "$DEV" ] && { echo "device did not appear"; cat "$log"; exit 1; }
export DEV LINUXID_CREDSTORE=$store
echo "== $DEV"
timeout 120 bash -c "$*"
rc=$?
echo "== rc=$rc; daemon log:"
cat "$log"
exit $rc
