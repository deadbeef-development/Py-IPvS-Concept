from typing import Tuple, Dict
from contextlib import contextmanager

import socks
from stem.control import Controller
from stem.response.add_onion import AddOnionResponse

@contextmanager
def connect_to_tor(dest_addr: Tuple[str, int]):
    sock = socks.socksocket()

    sock.set_proxy(proxy_type=socks.SOCKS5, addr='127.0.0.1', port=9050)
    sock.connect(dest_addr)

    try:
        yield sock
    finally:
        sock.close()

@contextmanager
def expose_to_tor(port_mappings: dict, key_type: str = 'NEW', key_content: str = 'BEST'):
    controller = Controller.from_port(port=9051)

    with controller:
        controller.authenticate()

        result: AddOnionResponse = controller.create_ephemeral_hidden_service(
            ports=port_mappings,
            await_publication=True,
            key_type=key_type,
            key_content=key_content
        )

        def cleanup():
            controller.remove_ephemeral_hidden_service(result.service_id)

        try:
            yield result
            cleanup()
            return
        except:
            cleanup()
            return

