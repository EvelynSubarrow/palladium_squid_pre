#!/usr/bin/env python3

import socket, select
from datetime import datetime
import ipaddress
import struct
import argparse

# Tredjepart!
from termcolor import colored

# Internal
from palladium_squid.socks5_util import (breakdown_socks_auth, form_response, SOCKS_ADDRESS_TYPES, SOCKS_COMMANDS,
                                         SOCKS_STATUS_COMMAND_UNSUPPORTED, SOCKS_STATUS_CONNECTION_NOT_ALLOWED,
                                         SOCKS_STATUS_SUCCESS)
from palladium_squid.util import dprint
from palladium_squid.ssh_tunnelling import carousel_from_file

SAFE_ASCII = range(32, 128)


class Client:
    def __init__(self, sock, control=False):
        if type(sock) in [tuple, list]:
            self.socket = sock[0]
        else:
            self.socket = sock

        self.phase = 0

        self.read_buffer = b""
        self.write_buffer = b""

        self.pair = None

        self.address = self.socket.getpeername()[0]
        if "." in self.address:
            self.address = self.address.replace("::ffff:", "")
        self.port = self.socket.getpeername()[1]

        self.ut_accepted = int(datetime.now().timestamp())
        self.is_control = control

    def fileno(self):
        return self.socket.fileno()

    def recv(self, bufsize, flags=0):
        return self.socket.recv(bufsize)

    def send(self, bytes, flags=0):
        return self.socket.send(bytes)

    def append_write(self, data: bytes):
        self.write_buffer += data
        write.append(self)

    def disconnect(self, reason = None):
        dprint(self, "--", 0, "Disconnected" + " (%s)" % reason if reason else "")
        self.socket.shutdown(socket.SHUT_RDWR)
        self.socket.close()
        for a in [read, write]:
            if self in a: a.remove(self)


def process(c: Client, carousel):
    if c.phase == 0:
        if len(c.read_buffer) >= 2:
            protocol_version = int(c.read_buffer[0])  # uint8, must be 0x05 for socks5
            auth_count = int(c.read_buffer[1])  # uint8 of following bytes
            if len(c.read_buffer) >= 2 + auth_count:
                auth_methods = c.read_buffer[2:2 + auth_count]
                if b'\x00' in auth_methods and protocol_version == 5: # 0x00 is nil auth
                    c.read_buffer = c.read_buffer[2+auth_count:]
                    c.phase = 1
                    dprint(c, "<<", True, f"SOCKS handshake v{protocol_version}, supports: {breakdown_socks_auth(auth_methods)}")
                    c.append_write(b"\x05\x00")  # "I am also v5, no auth"
                elif protocol_version != 5:
                    # There doesn't seem to be a polite way to deal with this
                    c.disconnect(f"Client v{protocol_version} version != 5")
                else:
                    c.append_write(b"\x05\xFF")  # "I am also v5, no mutual auth support, fuck off"
                    c.disconnect(f"Client v{protocol_version} either does not support v5 or does not support nil auth")
    elif c.phase == 1:
        if len(c.read_buffer) >= 7:  # Theoretical and very invalid minimum - a 0ch domain name
            protocol_version = int(c.read_buffer[0])
            command = int(c.read_buffer[1])
            reserved = int(c.read_buffer[2])
            address_type = int(c.read_buffer[3])

            address, port, encoded_address = None, None, None
            if address_type == 1 and len(c.read_buffer) >= 10:  # 4+2 (header+port trailer) + 4 octets
                address = ipaddress.IPv4Address(c.read_buffer[4:8])
                address = str(address).encode("ascii")
                port = struct.unpack("!H", c.read_buffer[8:10])[0]
                encoded_address = c.read_buffer[3:10]
                c.read_buffer = c.read_buffer[10:]
            elif address_type == 3:
                domain_length = int(c.read_buffer[4])
                if len(c.read_buffer) >= 7+domain_length:
                    address = c.read_buffer[5:5+domain_length]
                    port = struct.unpack("!H", c.read_buffer[5+domain_length:5+domain_length+2])[0]
                    encoded_address = c.read_buffer[3:5+domain_length+2]

                    c.read_buffer = c.read_buffer[5+domain_length+2:]

            elif address_type == 4 and len(c.read_buffer) >= 22:  # 4+2 + 16 ip6
                address = ipaddress.IPv6Address(c.read_buffer[4:20])
                address = str(address).encode("ascii")
                port = struct.unpack("!H", c.read_buffer[20:22])[0]
                encoded_address = c.read_buffer[3:22]
                c.read_buffer = c.read_buffer[22:]

            if address and port:
                c.phase = 2
                dprint(c, "<<", True, f"SOCKS {SOCKS_COMMANDS.get(command, 'Invalid command')} -> {SOCKS_ADDRESS_TYPES[address_type]} {address} :{port}")
                if command != 1:
                    # For now we don't support UDP or TCP bind
                    c.append_write(form_response(SOCKS_STATUS_COMMAND_UNSUPPORTED, encoded_address))
                elif any([int(a) not in SAFE_ASCII for a in address]):
                    # If it's not ascii you're doing something weird, go away
                    c.append_write(form_response(SOCKS_STATUS_CONNECTION_NOT_ALLOWED, encoded_address))
                    dprint(c, "--", True, f"Invalid characters in address")
                else:
                    # Let's assume we're O.K!
                    ssh_socket = carousel.setup(address.decode("ascii"), port)
                    if not ssh_socket:
                        c.append_write(form_response(SOCKS_STATUS_CONNECTION_NOT_ALLOWED,
                                                     b"\x01\x00\x00\x00\x00" + struct.pack("!H", c.port)))
                    else:
                        ssh_client = Client(ssh_socket)
                        ssh_client.phase = 3
                        ssh_client.pair = c
                        c.pair = ssh_client
                        c.phase = 2
                        read.append(ssh_client)
                        c.append_write(form_response(SOCKS_STATUS_SUCCESS,
                                                     b"\x01\x00\x00\x00\x00" + struct.pack("!H", c.port)))
    elif c.phase in [2, 3]:
        c.pair.append_write(c.read_buffer)
        c.read_buffer = b''
    else:
        dprint(c, "<<", 1, repr(c.read_buffer))


def server_socket(host, port, ip6=True):
    s_flags = socket.AF_INET6 if ip6 else socket.AF_INET
    s = socket.socket(s_flags)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(10)
    return s


# TODO: not this
read, write = [], []

def mainloop(socks_host, socks_port, carousel):
    global read, write
    server = server_socket(socks_host, socks_port)
    read = [server]
    write = []

    while True:
        r, w, x = select.select(read, write, [], 2)
        ut_now = int(datetime.now().timestamp())

        for c in r:
            if c in [server]:
                client = Client(server.accept(), False)
                dprint(client, "--", 1, "Connected (%s)" % client.port)
                read.append(client)
            else:
                new_data = c.recv(1024)
                if not len(new_data):
                    dprint(c, "--", 1, f"Disconnected by client ({c.port})")
                    for connection_list in [read, write]:
                        if c in connection_list:
                            connection_list.remove(c)
                else:
                    c.read_buffer += new_data
                    process(c, carousel)

        for c in write:
            if c.write_buffer:
                c.write_buffer = c.write_buffer[c.send(c.write_buffer):]
                if not c.write_buffer:
                    write.remove(c)

        for c in read + write:
            if c in [server] or c.is_control:
                continue
            if ut_now - c.ut_accepted >= 10 and c.phase not in [2, 3]:
                c.disconnect("Failed to complete SOCKS handshake in time")


def testloop(carousel):
    carousel.test_all()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-tor", "-N", action='store_true', default=False)

    parser.add_argument("--socks-bind", type=str, default="::", help="socks5 bind host")
    parser.add_argument("--socks-host", type=int, default=8090, help="socks5 bind port")

    action1 = parser.add_mutually_exclusive_group(required=True)
    action1.add_argument('--text-file', type=str, help='Use a text file of credentials formatted')

    action2 = parser.add_mutually_exclusive_group(required=True)
    action2.add_argument("-p", "--proxy", action='store_true', help="Presents a SOCKS proxy at the defined port")
    action2.add_argument("-t", "--test", action='store_true', help="Checks credentials, dumps to file")

    parser.add_argument("-o", "--output-file", help="File to dump text rows to")

    args = parser.parse_args()

    if args.text_file:
        with open(args.text_file) as f:
            file_carousel = carousel_from_file(f)

    if args.proxy:
        mainloop(args.socks_bind, args.socks_host, file_carousel)
    if args.test:
        testloop(file_carousel)
    if not args.no_tor:
        file_carousel.set_outbound_socks("localhost", 9050)

    if args.output_file:
        with open(args.output_file, "w") as f:
            for definition in file_carousel.get_transports():
                print(definition.dump(), file=f)

