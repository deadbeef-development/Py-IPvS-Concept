from typing import Callable, Tuple, Any
import threading

import paramiko as pko

from ..ssh_util import create_ipvs_ssh_server, connect_to_ipvs_ssh_server, IPVS_Request
from ..socket_util import transfer_echo

def start_thread(target: Callable[[], None], args: Tuple[Any, ...] = None) -> threading.Thread:
    if args is None:
        args = []
    
    t = threading.Thread(None, target, args=args)
    t.start()

    return t

def test_server_and_client():
    echo_test_port = 111

    client_key = pko.Ed25519Key.from_private_key_file('testkey/client')
    server_key = pko.Ed25519Key.from_private_key_file('testkey/server')

    def echo_handler(req: IPVS_Request):
        transfer_echo(req.chan)
    
    handlers = {
        echo_test_port: echo_handler
    }

    ###

    tcp_server = create_ipvs_ssh_server(handlers, server_key)
    start_thread(tcp_server.serve_forever)

    ###

    chan = connect_to_ipvs_ssh_server(tcp_server.server_address, echo_test_port, server_key, client_key)

    message = b"Hello world!\n"
    chan.send(message)
    data = chan.recv(len(message))

    is_same = (data == message)

    ###

    tcp_server.shutdown()
    
    ###

    try:
        print(f"Data matches: {is_same}")
        assert is_same
    finally:
        chan.close()

if __name__ == '__main__':
    test_server_and_client()

