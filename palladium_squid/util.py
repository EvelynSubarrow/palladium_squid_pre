import logging
from datetime import datetime
from termcolor import colored

log = logging.getLogger("PalladiumSquid")


def dprint(c, prefix, is_external, text, level=logging.DEBUG):
    log.log(level=level, msg=f"{c.address:>15}:{c.port:<5} {prefix} {text}")

def setup_logging(verbose):
    ch = logging.StreamHandler()

    log = logging.getLogger("PalladiumSquid")
    if verbose:
        ch.setLevel(logging.DEBUG)
        log.setLevel(logging.DEBUG)
    else:
        ch.setLevel(logging.INFO)
        log.setLevel(logging.INFO)
    log.propagate = False

    format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s", '%Y-%m-%dT%H:%M:%S%z')
    ch.setFormatter(format)
    log.addHandler(ch)


class SessionWrapper:
    def __init__(self, session_obj, commit=True):
        self.session_obj = session_obj
        self.session = None
        self.commit = commit

    def __enter__(self):
        self.session = self.session_obj()
        return self.session

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.session.rollback()
        elif self.commit:
            self.session.commit()
            self.session.flush()


def get_context_session(session_class):
    return SessionWrapper(session_class)
