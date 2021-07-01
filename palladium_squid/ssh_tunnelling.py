import logging
from io import StringIO
from threading import Thread, Lock
from typing import List, Optional, Tuple
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

from palladium_squid.util import dprint, get_context_session

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
    key_rel: KeyFileDefinition = relationship("KeyFileDefinition", uselist=False, lazy="select", innerjoin=True)

    hostname = Column(VARCHAR, nullable=False, primary_key=True)
    port = Column(SMALLINT, nullable=False, primary_key=True)
    auth_type_str = Column(VARCHAR, nullable=False)
    time_added = Column(TIMESTAMP, nullable=False)
    score = Column(INTEGER, nullable=False, default=0)

    last_connection = Column(TIMESTAMP, nullable=True)

    def get_private_key(self):
        if self.auth_type_str == "rsa":
            return paramiko.RSAKey.from_private_key(StringIO(self.key_rel.key_contents))
        elif self.auth_type_str == "ecdsa":
            return paramiko.ECDSAKey.from_private_key(StringIO(self.key_rel.key_contents))
        elif self.auth_type_str == "ed25519":
            return paramiko.Ed25519Key.from_private_key(StringIO(self.key_rel.key_contents))
        elif self.auth_type_str == "pass":
            return None
        else:
            raise ValueError(f"Unknown keytype {self.auth_type_str}")

    def get_outline(self):
        return SSHTransportOutline(self.username, self.hostname, self.port, self.password, self.get_private_key())

    def dump(self) -> str:
        return f"{self.score:<3} {self.username}@{self.hostname:16}" + f":{self.port}"*(self.port != 22) + \
               f" {self.auth_type_str:>5} " + (self.password or self.key_path)

    def index(self):
        return self._order


class SSHTransportOutline:
    def __init__(self, username, hostname, port, password, key):
        self.username = username
        self.password = password
        self.hostname = hostname
        self.port = port
        self.key = key

    # noinspection PyTypeChecker
    def pickup(self, proxy_pair) -> paramiko.Transport:
        if proxy_pair:
            s = socks.socksocket()
            s.set_proxy(socks.PROXY_TYPE_SOCKS5, *proxy_pair)
        else:
            s = socket()

        s.connect((self.hostname, self.port))

        transport = paramiko.Transport(s)
        transport.connect(username=self.username, password=self.password, pkey=self.key)
        return transport


class SSHTransportCarousel(Thread):
    def __init__(self, session_factory):
        super().__init__()
        self._outbound_socks_hostname = None
        self._outbound_socks_port = None
        self.session_factory = session_factory

    def run(self):
        while True:
            time.sleep(0.1)

    def next_transport_outline(self):
        with get_context_session(self.session_factory) as session:

            query = session.query(SSHTransportDefinition).\
                filter(SSHTransportDefinition.score == 0).order_by(SSHTransportDefinition.last_connection)
            if query.count():
                transport = query[0]
                transport.last_connection = datetime.now()
                session.commit()
                session.flush()

                return transport.get_outline()
            else:
                log.error("Run out of OK transports, woe")
                return None

    def setup(self, transport_outline, host, port) -> Tuple[Optional[socket], int]:
        return _establish(transport_outline, host, port, self.get_outbound_proxy())


    def set_outbound_socks(self, hostname, port):
        self._outbound_socks_hostname = hostname
        self._outbound_socks_port = port

    def get_outbound_proxy(self):
        if self._outbound_socks_hostname:
            return self._outbound_socks_hostname, self._outbound_socks_port

    def test_all(self):
        with get_context_session(self.session_factory) as session:
            for transport_def in session.query(SSHTransportDefinition).order_by(SSHTransportDefinition.time_added):
                # TODO: configurable test target
                sock, stat = _establish(transport_def.get_outline(), "example.com", 80, self.get_outbound_proxy())
                transport_def.score = stat
                if sock:
                    sock.close()

    def dump(self, filehandle):
        with get_context_session(self.session_factory) as session:
            for definition in session.query(SSHTransportDefinition).order_by(SSHTransportDefinition.time_added):
                print(definition.dump(), file=filehandle)

    def update_transport_score(self, outline: SSHTransportOutline, new_score: int):
        with get_context_session(self.session_factory) as session:
            update_values = {
                SSHTransportDefinition.score: new_score,
            }
            session.execute(update(SSHTransportDefinition, values=update_values).where(
                and_(
                    SSHTransportDefinition.hostname == outline.hostname,
                    SSHTransportDefinition.username == outline.username,
                    SSHTransportDefinition.port == outline.port,
                )
            ))
            session.commit()
            session.flush()


def _establish(definition: SSHTransportOutline, host, port, proxy_pair) -> Tuple[Optional[socket], int]:
    chan = None
    stat = 0
    try:
        ssh_transport = definition.pickup(proxy_pair)

        chan = ssh_transport.open_channel(
            "direct-tcpip",
            (host, port),
            ('Unknown', 0),  # This is supposed to be the peer name
        )
        if chan is None:
            stat = 1
    except socks.GeneralProxyError as e:
        chan = None
        log.error(f"General proxy error trying to connect to {host}:{port} via {definition.username}@{definition.hostname}:{definition.port}")
        stat = 2
    except paramiko.ssh_exception.SSHException:
        chan = None
        log.error(f"SSH error trying to connect to {host}:{port} via {definition.username}@{definition.hostname}:{definition.port}")
        stat = 3
    except TimeoutError:
        chan = None
        log.error(f"Timeout error trying to connect to {host}:{port} via {definition.username}@{definition.hostname}:{definition.port}")
        stat = 4
    except OSError:
        chan = None
        log.error(f"Timeout or OSError trying to connect to {host}:{port} via {definition.username}@{definition.hostname}:{definition.port}")
        stat = 5
    except EOFError:
        chan = None
        log.error(f"EOF error trying to connect to {host}:{port} via {definition.username}@{definition.hostname}:{definition.port}")
        stat = 6
    except Exception as e:
        log.error(f"Exception trying to connect to {host}:{port} via {definition.username}@{definition.hostname}:{definition.port}: " + traceback.format_exc())
        chan = None
        stat = 20

    return chan, stat


def get_host_port(full_host: str, default_port: int = 22):
    args = (full_host.split(":", 1) + [default_port])[:2]
    args[1] = int(args[1])
    return args[0], args[1]


def carousel_from_file(filehandle, session_factory) -> SSHTransportCarousel:
    with get_context_session(session_factory) as session:
        carousel = SSHTransportCarousel(session_factory)

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
            auth_type = auth_type.strip()
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
            elif auth_type.lower() in ["rsa", "ecdsa", "ed25519"]:
                private_key_path = auth
                auth_type_str = auth_type
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
            else:
                log.error(f"Can't process line {row_n+1}, don't recognise auth type {auth_type}")

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
            session.flush()
        return carousel
