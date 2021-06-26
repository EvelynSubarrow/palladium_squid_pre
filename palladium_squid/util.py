from datetime import datetime
from termcolor import colored

def dprint(c, prefix, is_external, text):
    iso_dt = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    print("%s %s %s %s" % (iso_dt, c.address, prefix, colored(text, "cyan") if is_external else text))
