import socket
import paramiko
from typing import Tuple, Dict, Callable
import json

from socket_util import Request, create_tcp_server, transfer

LOOPBACK = '127.0.0.1'
IPVS_USERNAME = 'ipvs'
IPVS_INFO_PORT = 230

Channel_Handler = Callable[[paramiko.Channel], None]

def proxy_pass(chan: paramiko.Channel, dest_addr: Tuple[str, int]):
    dest_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dest_sock.connect(dest_addr)

    transfer(chan, dest_sock)
    
    try:
        chan.close()
    finally:
        dest_sock.close()

class _IPVS_SSH_Server_Handler(paramiko.ServerInterface):
    def __init__(self, channel_handlers: Dict[int, Channel_Handler], ipvs_info: Dict):
        super().__init__()
        self.channel_handlers = channel_handlers
        self.ipvs_info = ipvs_info
        
        # (Chanid, Dest Port)
        self.pending_tcpip_request_channels: Dict[int, int] = dict()
    
    def check_auth_publickey(self, username: str, key: paramiko.PKey):
        if username == 'ipvs':
            return paramiko.AUTH_SUCCESSFUL
        
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "publickey"
    
    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        origin_host, origin_port = origin
        dest_host, dest_port = destination

        is_valid_port = (dest_port in self.channel_handlers) or (dest_port == IPVS_INFO_PORT)

        if (dest_host == LOOPBACK) and (is_valid_port):
            self.pending_tcpip_request_channels[chanid] = dest_port
            return paramiko.OPEN_SUCCEEDED

        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

def create_ipvs_ssh_server(
        ssh_bind_addr: Tuple[str, int],
        channel_handlers: Dict[int, Channel_Handler],
        ipvs_info: dict,
        host_key: paramiko.PKey
):
    ssh_server_handler = _IPVS_SSH_Server_Handler(channel_handlers, ipvs_info)

    def handle_json_info(chan: paramiko.Channel):
        info_json = json.dumps(ipvs_info).encode()
        chan.send(info_json)

    def handle_request(req: Request):
        transport = paramiko.Transport(req.request)
        transport.add_server_key(host_key)
        transport.start_server(server=ssh_server_handler)

        chan = transport.accept()

        if (chan is None) or (not chan.active):
            return
        else:
            dest_port = ssh_server_handler.pending_tcpip_request_channels[chan.chanid]

            if dest_port == IPVS_INFO_PORT:
                handle_channel = handle_json_info
            else:
                handle_channel = channel_handlers[dest_port]

            try:
                handle_channel(chan)
            finally:
                chan.close()

    server = create_tcp_server(ssh_bind_addr, handle_request)

    return server

