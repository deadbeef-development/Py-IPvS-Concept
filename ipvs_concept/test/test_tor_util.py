import socketserver
import threading
from time import sleep
from contextlib import contextmanager
import logging

import paramiko as pko
from stem.util import log as stem_log

from ..socket_util import Request, create_tcp_server, transfer_echo
from ..tor_util import expose_to_tor, connect_to_tor

stem_log.get_logger().level = logging.DEBUG

TEST_TARGET_PORT = 1234
TEST_HIDDEN_SERVICE_PORT = 4321
TEST_DATA = b"TEST_DATA"

@contextmanager
def run_echo_server():
    def handle_request(req: Request):
        transfer_echo(req.sock)

    bind_addr = ('127.0.0.1', TEST_TARGET_PORT)
    server: socketserver.TCPServer = create_tcp_server(bind_addr, handle_request)

    t = threading.Thread(None, server.serve_forever, daemon=True)
    t.start()

    try:
        yield server
    finally:
        server.shutdown()

# Unofficial
def __main__(args: list[str]):
    port_mappings = {
        TEST_HIDDEN_SERVICE_PORT: TEST_TARGET_PORT
    }

    with run_echo_server() as server:
        with expose_to_tor(port_mappings) as result:
            onion_host = result.service_id + '.onion'
            
            onion_addr = (onion_host, TEST_HIDDEN_SERVICE_PORT)

            with connect_to_tor(onion_addr) as sock:
                sock.send(TEST_DATA)

                sleep(0.1)

                echoed_data = sock.recv(len(TEST_DATA))

                assert echoed_data == TEST_DATA

                sock.close()

if __name__ == '__main__':
    import sys
    __main__(sys.argv)


