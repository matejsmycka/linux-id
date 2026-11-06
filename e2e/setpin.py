"""Set a PIN on the device run.sh started: setpin.py <e2e dir> <pin>."""
import sys; sys.path.insert(0, sys.argv[1])
from fidodev import device
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin
ClientPin(Ctap2(device())).set_pin(sys.argv[2])
