from typing import Callable, Tuple
import socket, socketserver
import threading
from contextlib import contextmanager

TRANSFER_BUF_SIZE = 2**13

class Request:
    sock: socket.socket
    client_address: Tuple[str, int]
    server: socketserver.BaseServer

    def __init__(self, handler: socketserver.BaseRequestHandler):
        self.sock = handler.request
        self.client_address = handler.client_address
        self.server = handler.server

@contextmanager
def create_tcp_server(bind_addr: Tuple[str, int], handle_request: Callable[[Request], None]) -> socketserver.TCPServer:
    class TCP_Handler(socketserver.BaseRequestHandler):
        def handle(self):
            req = Request(self)
            return handle_request(req)

    class Threaded_TCP_Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
        pass

    server = Threaded_TCP_Server(bind_addr, TCP_Handler)

    return server

def serve_file_tcp(bind_addr: Tuple[str, int], content: bytes):
    def handle_request(req: Request):
        req.sock.send(content)
        req.sock.close()
    
    return create_tcp_server(bind_addr, handle_request)

def _transfer1(source: socket.socket, dest: socket.socket):
    while True:
        data = source.recv(TRANSFER_BUF_SIZE)

        if data:
            dest.send(data)
        else:
            break

def transfer(sock1: socket.socket, sock2: socket.socket):
    t1 = threading.Thread(None, _transfer1, args=(sock1, sock2), daemon=True)
    t2 = threading.Thread(None, _transfer1, args=(sock2, sock1), daemon=True)

    t1.start()
    t2.start()

    t1.join()
    t2.join()

def transfer_echo(sock: socket.socket):
    _transfer1(sock, sock)

def receive_all(source: socket.socket) -> bytes:
    result = bytearray()

    while True:
        data = source.recv(TRANSFER_BUF_SIZE)

        if data:
            result.extend(data)
        else:
            break
    
    return bytes(result)

