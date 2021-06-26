import struct

SOCKS_AUTH_METHODS = {
    0x00: "Nil",
    0x01: "RFC1961 GSSAPI",
    0x02: "RFC1929 User/pass",
    0x03: "IANA challenge-handshake proto",
    0x04: "IANA unassigned",
    0x05: "IANA challenge-response method",
    0x06: "IANA SSL",
    0x07: "IANA NDS",
    0x08: "IANA Multi",
    0x09: "IANA JSON",
}

SOCKS_ADDRESS_TYPES = {
    0x01: "IPv4",
    0x03: "domain",
    0x04: "IPv6",
}

SOCKS_COMMANDS = {
    0x01: "CONNECT",
    0x02: "BIND",
    0x03: "UDP",
}

SOCKS_STATUS_SUCCESS = 0x00
SOCKS_STATUS_GENERAL_FAILURE = 0x01
SOCKS_STATUS_CONNECTION_NOT_ALLOWED = 0x02
SOCKS_STATUS_NETWORK_UNREACHABLE = 0x03
SOCKS_STATUS_HOST_UNREACHABLE = 0x04
SOCKS_STATUS_CONNECTION_REFUSED = 0x05
SOCKS_STATUS_TTL_EXPIRED = 0x06
SOCKS_STATUS_COMMAND_UNSUPPORTED = 0x07
SOCKS_STATUS_UNSUPPORTED_ADDRESS = 0x08


def breakdown_socks_auth(auth_string: bytes):
    return ", ".join([f"""0x{a:02x} '{SOCKS_AUTH_METHODS.get(int(a), "Unknown")}'""" for a in auth_string])


def form_response(status, formed_address):
    return struct.pack("!BBB", 5, status, 0) + formed_address
