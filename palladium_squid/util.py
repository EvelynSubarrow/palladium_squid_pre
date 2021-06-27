import logging
from datetime import datetime
from termcolor import colored

log = logging.getLogger("PalladiumSquid")


def dprint(c, prefix, is_external, text):
    log.info(f"{c.address:>15}:{c.port:<5} {prefix} {text}")

def setup_logging():
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    log = logging.getLogger("PalladiumSquid")
    log.setLevel(logging.DEBUG)
    log.propagate = False

    format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s", '%Y-%m-%dT%H:%M:%S%z')
    ch.setFormatter(format)
    log.addHandler(ch)
