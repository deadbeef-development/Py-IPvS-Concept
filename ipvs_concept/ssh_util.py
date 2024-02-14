import socket
from typing import Tuple, Dict, Callable, Optional
import json

import paramiko as pko

from .socket_util import Request, create_tcp_server, transfer, receive_all

LOOPBACK = '127.0.0.1'
IPVS_USERNAME = 'ipvs'

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

def get_proxy_pass_handler(dest_addr: Tuple[str, int]):
    def proxy_pass_Handler(req: IPVS_Request):
        proxy_pass(req.chan, dest_addr)
    
    return proxy_pass_Handler

# Designed for only one instance per transport.
class _IPVS_SSH_Server_Handler(pko.ServerInterface):
    def __init__(self, ipvs_req_handlers: Dict[int, IPVS_Request_Handler]):
        super().__init__()
        self.ipvs_req_handlers = ipvs_req_handlers
        
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

        is_valid_port = (dest_port in self.ipvs_req_handlers)

        if (dest_host == LOOPBACK) and (is_valid_port):
            self.dest_port = dest_port
            return pko.OPEN_SUCCEEDED

        return pko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

def create_ipvs_ssh_server(
        ipvs_req_handlers: Dict[int, IPVS_Request_Handler],
        host_key: pko.PKey,
        bind_addr: Optional[Tuple[str, int]] = None
):
    if bind_addr is None:
        bind_addr = ('127.0.0.1', 0)
    
    def handle_request(req: Request):
        ssh_server_handler = _IPVS_SSH_Server_Handler(ipvs_req_handlers)

        transport = pko.Transport(req.request)
        transport.add_server_key(host_key)
        transport.start_server(server=ssh_server_handler)

        chan = transport.accept()

        if (chan is None) or (not chan.active):
            return
        else:
            client_identity = ssh_server_handler.client_identity
            dest_port = ssh_server_handler.dest_port

            handle_channel = ipvs_req_handlers[dest_port]
            
            req = IPVS_Request(chan, client_identity)

            try:
                handle_channel(req)
            finally:
                chan.close()

    server = create_tcp_server(bind_addr, handle_request)

    return server

def get_pubkey_from_ipvs_address(ipvs_addr: str) -> pko.PKey:
    parts = ipvs_addr.strip().lower().split('.')

    if parts[-1] != 'ipvs':
        raise ValueError("Not an IPVS address")

    # <pubkey hex>.<pubkey type>.ipvs

    pubkey_hex = parts[-3]
    pubkey_type = 'ssh-' + parts[-2]
    
    pubkey_bytes = bytes.fromhex(pubkey_hex)

    return pko.PKey.from_type_string(pubkey_type, pubkey_bytes)

def connect_to_ipvs_ssh_server(
        ssh_server_addr: Tuple[str, int], dest_port: int, 
        ssh_server_pubkey: pko.PKey, client_identity: pko.PKey, 
        existing_socket: socket.socket = None
):
    ssh_host, ssh_port = ssh_server_addr

    host_entry = f"[{ssh_host}]:{ssh_port}"

    ssh_client = pko.SSHClient()
    ssh_client.get_host_keys().add(host_entry, ssh_server_pubkey.get_name(), ssh_server_pubkey)

    ssh_client.connect(
        hostname=ssh_host,
        port=ssh_port,
        username=IPVS_USERNAME,
        pkey=client_identity,
        sock=existing_socket
    )

    dest_addr = ('127.0.0.1', dest_port)
    src_addr = ('127.0.0.1', 0)

    transport = ssh_client.get_transport()
    chan = transport.open_channel('direct-tcpip', dest_addr, src_addr)

    return chan

