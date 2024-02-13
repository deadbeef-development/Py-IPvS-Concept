import socket
import paramiko as pko
from typing import Tuple, Dict, Callable
import json

from socket_util import Request, create_tcp_server, transfer

LOOPBACK = '127.0.0.1'
IPVS_USERNAME = 'ipvs'
IPVS_INFO_PORT = 230

class IPVS_Request:
    def __init__(self, chan: pko.Channel, client_identity: pko.PKey):
        self.chan = chan
        self.identity = client_identity

IPVS_Request_Handler = Callable[[IPVS_Request], None]

def proxy_pass(chan: pko.Channel, dest_addr: Tuple[str, int]):
    dest_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dest_sock.connect(dest_addr)

    transfer(chan, dest_sock)
    
    try:
        chan.close()
    finally:
        dest_sock.close()

# Designed for only one instance per transport.
class _IPVS_SSH_Server_Handler(pko.ServerInterface):
    def __init__(self, ipvs_req_handlers: Dict[int, IPVS_Request_Handler], ipvs_info: Dict):
        super().__init__()
        self.ipvs_req_handlers = ipvs_req_handlers
        self.ipvs_info = ipvs_info
        
        self.client_identity = None
        self.dest_port = None
    
    def check_auth_publickey(self, username: str, key: pko.PKey):
        if username == 'ipvs':
            self.client_identity = key
            return pko.AUTH_SUCCESSFUL
        
        return pko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "publickey"
    
    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        origin_host, origin_port = origin
        dest_host, dest_port = destination

        is_valid_port = (dest_port in self.ipvs_req_handlers) or (dest_port == IPVS_INFO_PORT)

        if (dest_host == LOOPBACK) and (is_valid_port):
            self.dest_port = dest_port
            return pko.OPEN_SUCCEEDED

        return pko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

def create_ipvs_ssh_server(
        ssh_bind_addr: Tuple[str, int],
        ipvs_req_handlers: Dict[int, IPVS_Request_Handler],
        ipvs_info: dict,
        host_key: pko.PKey
):
    def handle_json_info(req: IPVS_Request):
        info_json = json.dumps(ipvs_info).encode()
        req.chan.send(info_json)

    def handle_request(req: Request):
        ssh_server_handler = _IPVS_SSH_Server_Handler(ipvs_req_handlers, ipvs_info)

        transport = pko.Transport(req.request)
        transport.add_server_key(host_key)
        transport.start_server(server=ssh_server_handler)

        chan = transport.accept()

        if (chan is None) or (not chan.active):
            return
        else:
            client_identity = ssh_server_handler.client_identity
            dest_port = ssh_server_handler.dest_port

            if dest_port == IPVS_INFO_PORT:
                handle_channel = handle_json_info
            else:
                handle_channel = ipvs_req_handlers[dest_port]
            
            req = IPVS_Request(chan, client_identity)

            try:
                handle_channel(req)
            finally:
                chan.close()

    server = create_tcp_server(ssh_bind_addr, handle_request)

    return server

