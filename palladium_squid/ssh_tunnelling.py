from threading import Thread, Lock
import time
from socket import socket

import paramiko

from palladium_squid.util import dprint


class SSHTransportDefinition:
    def __init__(self, hostname: str, port: int, username: str, password = None, private_key = None, host_key = None):
        self.username = username
        self.password = password
        self.private_key = private_key
        self.host_key = host_key
        self.hostname = hostname
        self.port = port

    # noinspection PyTypeChecker
    def pickup(self) -> paramiko.Transport:
        transport = paramiko.Transport((self.hostname, self.port))
        transport.connect(hostkey=self.host_key, username=self.username, password=self.password, pkey=self.private_key)
        print(transport.is_authenticated())
        return transport


class SSHTransportCarousel(Thread):
    def __init__(self):
        super().__init__()
        self.transport_definitions = []

    def run(self):
        while True:
            time.sleep(0.1)

    def setup(self, host, port) -> socket:
        definition = self.transport_definitions.pop()
        self.transport_definitions.insert(0, definition)
        ssh_transport = definition.pickup()
        chan = ssh_transport.open_channel(
            "direct-tcpip",
            (host, port),
            ('Unknown', 0),  # This is supposed to be the peer name
        )

        if chan is None:
            print("Rejected")
        return chan


def get_host_port(full_host: str, default_port: int = 22):
    args = (full_host.split(":", 1) + [default_port])[:2]
    args[1] = int(args[1])
    return args[0], args[1]


def carousel_from_file(filehandle) -> SSHTransportCarousel:
    carousel = SSHTransportCarousel()

    for line in filehandle:
        remainder = line.rstrip("\n")
        username, remainder = remainder.split("@", 1)
        full_host, remainder = remainder.split(" ", 1)
        remainder = remainder.lstrip()

        auth_type, auth = remainder.split(" ", 1)
        username = username.lstrip()
        hostname, port = get_host_port(full_host.strip())

        password = None
        private_key = None

        if auth_type.lower() in ["pass", "password", "p"]:
            password = auth
        if auth_type.lower() in ["rsa"]:
            private_key = paramiko.RSAKey.from_private_key_file(auth)

        carousel.transport_definitions.append(SSHTransportDefinition(hostname, port, username, password, private_key))

    return carousel
