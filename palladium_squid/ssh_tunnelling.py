from threading import Thread, Lock
from typing import List
import time
from socket import socket
import traceback

import paramiko

from palladium_squid.util import dprint

import socks


class SSHTransportDefinition:
    def __init__(self, hostname: str, port: int, username: str, password = None, private_key = None, host_key = None,
                 score=0, private_key_path=None, auth_type_str=None, order=None):
        self._username = username
        self._password = password
        self._private_key = private_key
        self._host_key = host_key
        self._hostname = hostname
        self._port = port
        self._score = score
        self._private_key_path = private_key_path
        self._auth_type_str = auth_type_str
        self._order = order

    # noinspection PyTypeChecker
    def pickup(self, proxy_pair) -> paramiko.Transport:
        if proxy_pair:
            s = socks.socksocket()
            s.set_proxy(socks.PROXY_TYPE_SOCKS5, *proxy_pair)
        else:
            s = socket()

        s.connect((self._hostname, self._port))

        transport = paramiko.Transport(s)
        transport.connect(hostkey=self._host_key, username=self._username, password=self._password, pkey=self._private_key)
        return transport

    def dump(self) -> str:
        return f"{self._score:<3} {self._username}@{self._hostname:16}" + f":{self._port}"*(self._port != 22) + \
               f" {self._auth_type_str:>5} " + (self._password or self._private_key_path)

    def index(self):
        return self._order



class SSHTransportCarousel(Thread):
    def __init__(self):
        super().__init__()
        self.transport_definitions = []
        self._outbound_socks_hostname = None
        self._outbound_socks_port = None

    def run(self):
        while True:
            time.sleep(0.1)

    def setup(self, host, port) -> socket:
        definition = self.transport_definitions.pop()
        self.transport_definitions.insert(0, definition)

        return _establish(definition, host, port, self.get_outbound_proxy())

    def get_transports(self) -> List[SSHTransportDefinition]:
        return sorted(self.transport_definitions, key=lambda x: x.index())

    def set_outbound_socks(self, hostname, port):
        self._outbound_socks_hostname = hostname
        self._outbound_socks_port = port

    def get_outbound_proxy(self):
        if self._outbound_socks_hostname:
            return self._outbound_socks_hostname, self._outbound_socks_port

    def test_all(self):
        for transport_def in self.get_transports():
            # TODO: configurable test target
            sock = _establish(transport_def, "example.com", 80, self.get_outbound_proxy())
            if sock:
                sock.close()


def _establish(definition, host, port, proxy_pair) -> socket:
    chan = None
    try:
        ssh_transport = definition.pickup(proxy_pair)

        chan = ssh_transport.open_channel(
            "direct-tcpip",
            (host, port),
            ('Unknown', 0),  # This is supposed to be the peer name
        )
    except Exception as e:
        chan = None
    if chan is None:
        definition._score = 1
    return chan


def get_host_port(full_host: str, default_port: int = 22):
    args = (full_host.split(":", 1) + [default_port])[:2]
    args[1] = int(args[1])
    return args[0], args[1]


def carousel_from_file(filehandle) -> SSHTransportCarousel:
    carousel = SSHTransportCarousel()

    for row_n, line in enumerate(filehandle):
        remainder = line.rstrip("\n")
        username, remainder = remainder.split("@", 1)
        score = ""
        if " " in username:
            score, username = username.split(" ", 1)
        full_host, remainder = remainder.split(" ", 1)
        remainder = remainder.lstrip()

        auth_type, auth = remainder.split(" ", 1)
        username = username.strip()
        score = score.strip()
        if score:
            score = int(score)
        else:
            score = 0
        hostname, port = get_host_port(full_host.strip())

        password = None
        private_key = None
        private_key_path = None
        auth_type_str = None

        if auth_type.lower() in ["pass", "password", "p", "pas"]:
            password = auth
            auth_type_str = "pass"
        elif auth_type.lower() in ["rsa"]:
            private_key = paramiko.RSAKey.from_private_key_file(auth)
            private_key_path = auth
            auth_type_str = "rsa"

        carousel.transport_definitions.append(
            SSHTransportDefinition(hostname, port, username, password, private_key,
                                   score=score, private_key_path=private_key_path,
                                   auth_type_str=auth_type_str, order=row_n))

    return carousel
