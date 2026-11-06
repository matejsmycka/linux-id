"""Open exactly the device run.sh started (never the user's real linux-id)."""
import os
from fido2.hid import CtapHidDevice
from fido2.hid.linux import get_descriptor, open_connection

def device():
    path = os.environ["DEV"]
    return CtapHidDevice(get_descriptor(path), open_connection(get_descriptor(path)))
