from typing import Dict, Tuple
import json
from contextlib import contextmanager

import paramiko as pko
import ngrok

from .socket_util import receive_all, create_tcp_server, Request
from .ssh_util import connect_to_ipvs_ssh_server, create_ipvs_ssh_server, IPVS_Request_Handler
from .tor_util import connect_to_tor, expose_to_tor

IPVS_PROTOCOL_VERSION = 1
IPVS_PROTOCOL_VERSION_KEY = 'ipvs_version'
IPVS_ONION_HANDSHAKE_PORT = 230

METHOD_SSH_DIRECT = 'ssh_direct'

class No_Methods_Available(Exception): ...

class IPVS_Secret_File:
    tor_key_type: str
    tor_key_content: str

    def __init__(self, filepath: str):
        self.filepath = filepath
    
    def __enter__(self):
        ... # TODO: Load file
        return self

    def __exit__(self, exc_type, exc, exc_tb):
        ... # TODO: Save file

def decode_pubkey_from_str(pubkey: str) -> pko.PKey:
    ... # TODO

def encode_pubkey_to_str(pubkey: pko.PKey) -> str:
    ... # TODO

def expose_with_ngrok(port: int):
    ... # TODO

    public_addr: Tuple[str, int] = ... # TODO

    try:
        yield public_addr
    finally:
        ... # TODO: Cleanup

def generate_pubkey() -> pko.PKey:
    ... # TODO

@contextmanager
def connect(ipvs_host: str, port: int, client_identity: pko.PKey = None):
    ipvs_index = ipvs_host.index('.ipvs')
    onion_host = ipvs_host[:ipvs_index] + '.onion'

    onion_addr = (onion_host, IPVS_ONION_HANDSHAKE_PORT)

    handshake_req = {
        IPVS_PROTOCOL_VERSION_KEY: IPVS_PROTOCOL_VERSION
    }

    request_data = json.dumps(handshake_req).encode()

    with connect_to_tor(onion_addr) as sock:
        sock.send(request_data)
        response_data = receive_all(sock)

    response = json.loads(response_data)

    failed_attempts = list()

    for meth in response['methods']:
        if meth['type'] == METHOD_SSH_DIRECT:
            meth_args = meth['args']

            ssh_server_addr: Tuple[str, int] = meth_args['ssh_server_address']
            ssh_server_pubkey: pko.PKey = decode_pubkey_from_str(meth_args['ssh_public_key'])

            context_error = None

            try:
                with connect_to_ipvs_ssh_server(ssh_server_addr, port, ssh_server_pubkey, client_identity) as chan:
                    try:
                        chan: pko.Channel
                        yield chan
                    except Exception as context_error:
                        pass
            except Exception as attempt_failed:
                failed_attempts.append(attempt_failed)
            
            if context_error is not None:
                raise context_error

    if len(failed_attempts) > 0:
        raise No_Methods_Available(failed_attempts)
    else:
        raise No_Methods_Available

@contextmanager
def serve(ipvs_req_handlers: Dict[int, IPVS_Request_Handler], ipvs_secret_file: str):
    host_key: pko.PKey = generate_pubkey()
    ssh_bind_addr = ('127.0.0.1', 0)
    handshake_server_bind_addr = ('127.0.0.1', 0)

    with create_ipvs_ssh_server(ipvs_req_handlers, host_key, ssh_bind_addr) as ssh_server:
        ssh_backend_host, ssh_backend_port = ssh_server.server_address

        with expose_with_ngrok(ssh_backend_port) as ssh_public_addr:
            def handshake_handler(req: Request):
                handshake_request_data = receive_all(req.sock)

                handshake_request = json.loads(handshake_request_data)

                if handshake_request[IPVS_PROTOCOL_VERSION_KEY] == 1:
                    handshake_response = {
                        'methods': [
                            {
                                'type': METHOD_SSH_DIRECT,
                                'args': {
                                    'ssh_server_address': ssh_public_addr,
                                    'ssh_public_key': encode_pubkey_to_str(host_key)
                                }
                            }
                        ]
                    }

                    handshake_response_data = json.dumps(handshake_response).encode()

                    req.sock.send(handshake_response_data)

                    req.sock.close()
                else:
                    req.sock.close()
            
            with create_tcp_server(handshake_server_bind_addr, handshake_handler) as handshake_server:
                hs_backend_host, hs_backend_port = handshake_server.server_address

                port_mappings = {
                    IPVS_ONION_HANDSHAKE_PORT: hs_backend_port
                }

                with IPVS_Secret_File(ipvs_secret_file) as ipvssf:
                    with expose_to_tor(port_mappings, ipvssf.tor_key_type, ipvssf.tor_key_content) as result:
                        ipvs_addr = result.service_id + '.ipvs'
                        yield ipvs_addr



