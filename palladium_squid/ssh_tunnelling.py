import logging
from io import StringIO
from threading import Thread, Lock
from typing import List, Optional
import time
from socket import socket
import traceback
from datetime import datetime

import paramiko
import socks
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy import Column, ForeignKey, ForeignKeyConstraint, UniqueConstraint, CHAR, VARCHAR, JSON, SMALLINT, \
    INTEGER, DATE, BOOLEAN, TIMESTAMP, TIME, ARRAY, BLOB, and_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import update

from palladium_squid.util import dprint

log = logging.getLogger("PalladiumSquid")

Base = declarative_base()


def create_all(engine):
    Base.metadata.create_all(engine)


class KeyFileDefinition(Base):
    __tablename__ = "palladium_squid_private_keys"
    key_path = Column(VARCHAR, nullable=False, primary_key=True)
    key_contents = Column(VARCHAR, nullable=False)


class SSHTransportDefinition(Base):
    __tablename__ = "palladium_squid_credentials"
    __table_args__ = (
        UniqueConstraint("username", "hostname", "port"),
    )
    username = Column(VARCHAR, nullable=False, primary_key=True)
    password = Column(VARCHAR, nullable=True)
    key_path = Column(VARCHAR, ForeignKey(KeyFileDefinition.key_path), nullable=True)
    key_rel: KeyFileDefinition = relationship("KeyFileDefinition", uselist=False, lazy="joined", innerjoin=True)

    hostname = Column(VARCHAR, nullable=False, primary_key=True)
    port = Column(SMALLINT, nullable=False, primary_key=True)
    auth_type_str = Column(VARCHAR, nullable=False)
    time_added = Column(TIMESTAMP, nullable=False)
    score = Column(INTEGER, nullable=False, default=0)

    last_connection = Column(TIMESTAMP, nullable=True)

    def get_private_key(self):
        if self.auth_type_str == "rsa":
            return paramiko.RSAKey.from_private_key(StringIO(self.key_rel.key_contents))

    # noinspection PyTypeChecker
    def pickup(self, proxy_pair) -> paramiko.Transport:
        if proxy_pair:
            s = socks.socksocket()
            s.set_proxy(socks.PROXY_TYPE_SOCKS5, *proxy_pair)
        else:
            s = socket()

        s.connect((self.hostname, self.port))

        transport = paramiko.Transport(s)
        transport.connect(username=self.username, password=self.password, pkey=self.get_private_key())
        return transport

    def dump(self) -> str:
        return f"{self.score:<3} {self.username}@{self.hostname:16}" + f":{self.port}"*(self.port != 22) + \
               f" {self.auth_type_str:>5} " + (self.password or self.key_path)

    def index(self):
        return self._order


class SSHTransportCarousel(Thread):
    def __init__(self, session: Session, session_factory):
        super().__init__()
        self._outbound_socks_hostname = None
        self._outbound_socks_port = None
        self.session = session
        self.session_factory = session_factory

    def run(self):
        while True:
            time.sleep(0.1)

    def setup(self, host, port) -> Optional[socket]:
        query = self.session.query(SSHTransportDefinition).\
            filter(SSHTransportDefinition.score == 0).order_by(SSHTransportDefinition.last_connection)

        if query.count():
            return _establish(query[0], host, port, self.get_outbound_proxy())
        else:

            # TODO: dire error message
            return None

    def get_transports(self) -> List[SSHTransportDefinition]:
        return self.session.query(SSHTransportDefinition).order_by(SSHTransportDefinition.time_added)

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
        definition.last_connection = datetime.now()
        ssh_transport = definition.pickup(proxy_pair)

        chan = ssh_transport.open_channel(
            "direct-tcpip",
            (host, port),
            ('Unknown', 0),  # This is supposed to be the peer name
        )
    except Exception as e:
        print(traceback.format_exc())
        chan = None
    if chan is None:
        definition._score = 1
    return chan


def get_host_port(full_host: str, default_port: int = 22):
    args = (full_host.split(":", 1) + [default_port])[:2]
    args[1] = int(args[1])
    return args[0], args[1]


def carousel_from_file(filehandle, session: Session, session_factory) -> SSHTransportCarousel:
    carousel = SSHTransportCarousel(session, session_factory)

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
            private_key_path = auth
            auth_type_str = "rsa"
            with open(private_key_path, "r") as f:
                query = session.query(KeyFileDefinition).filter(KeyFileDefinition.key_path == private_key_path)
                if not query.count():
                    session.add(KeyFileDefinition(key_path=private_key_path, key_contents=f.read()))
                else:
                    update_values = {
                        KeyFileDefinition.key_contents: f.read()
                    }
                    session.execute(update(KeyFileDefinition, values=update_values).where(
                        KeyFileDefinition.key_path == private_key_path))

        query = session.query(SSHTransportDefinition).filter(and_(SSHTransportDefinition.hostname == hostname,
                                                             SSHTransportDefinition.username == username,
                                                             SSHTransportDefinition.port == port))
        if not query.count():
            session.add(SSHTransportDefinition(hostname=hostname, port=port, username=username, password=password,
                                   score=score, key_path=private_key_path,
                                   auth_type_str=auth_type_str, time_added=datetime.utcnow()))
        else:
            update_values = {
                SSHTransportDefinition.password: password,
                SSHTransportDefinition.key_path: private_key_path,
                SSHTransportDefinition.auth_type_str: auth_type_str
            }
            session.execute(update(SSHTransportDefinition, values=update_values).where(
                and_(SSHTransportDefinition.hostname == hostname,
                     SSHTransportDefinition.username == username,
                     SSHTransportDefinition.port == port)
            ))
        session.commit()
    return carousel
