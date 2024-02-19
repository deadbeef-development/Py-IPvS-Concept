from typing import Tuple, Dict
from contextlib import contextmanager

import socks
from stem.control import Controller
from stem.response.add_onion import AddOnionResponse
from stem import process

def connect_to_tor(dest_addr: Tuple[str, int]) -> socks.socksocket:
    sock = socks.socksocket()

    sock.set_proxy(proxy_type=socks.SOCKS5, addr='127.0.0.1', port=9050)
    sock.connect(dest_addr)

    return sock

@contextmanager
def expose_to_tor(port_mappings: Dict[int, int], key_type: str = 'NEW', key_content: str = 'BEST'):
    tor_process = process.launch_tor_with_config(
        config = {
            'ControlPort': '9051',
            'SocksPort': '9050',
        },
        init_msg_handler = print,
    )

    with Controller.from_port(port=9051) as controller:
        controller.authenticate()

        result: AddOnionResponse = controller.create_ephemeral_hidden_service(
            ports=port_mappings,
            await_publication=True,
            key_type=key_type,
            key_content=key_content
        )

        try:
            yield result
        finally:
            controller.remove_ephemeral_hidden_service(result.service_id)
            tor_process.terminate()
