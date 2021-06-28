# Palladium Squid
VPNs are hard, SOCKS just isn't very secure now is it, but everyone and their mum can set up SSH. Unfortunately most
things don't know how to use SSH as a proxy. So, this lets you maintain a list of SSH credentials, and transparently
cycle between them behind a SOCKS5 proxy.

## Using signal, using tor
This tool connects via tor in every mode by default, looking for it on a SOCKS5 proxy at localhost:9050. If you install
the tor service on Linux you should get this by default. It's not currently configurable, but you can disable
using `--no-tor`.

## Credential file format

In every mode, if you specify a permanent database and also a text file, the contents of the text file will be added
to the database or used to update it. Score is only used first time and not updated, so using a single master list will
_not_ increase the failure rate by rescoring unusable transports.

Transports are distinguished by username, hostname, and port in combination.

|score |host |authtype |auth 
--- | --- | --- | ---
|0 if OK|username@host:port|"pass"/keytype|password/filename|

PalladiumSquid relies on a basic scoring system for credentials. The initial score is 0, a nonzero score
indicates either the transport was unusable when tested, or failed during use. If you're writing a file for import,
set the score to 0.

If you're authenticating with a password, set the authtype to "pass", and enter the password. If you're authenticating
with a key, give the type of key as the authtype. Keys are cached in the database against their supplied filename,
and when the database is dumped, it'll reference the original source filename.

Currently supported key types:
* RSA ('rsa')
* ECDSA ('ecdsa')
* ED25519 ('ed25519')

The file format is _not_ tolerant of tabs, at least one space must separate fields. The final field must be separated
by only _one_ space (it has to be constant because passwords can begin with spaces)

It's also case-sensitive in pretty much every field for now, that's a password not a PASSword.

### Example
```
0 root@123.45.67.89   rsa /home/boris/.ssh/id_rsa
0 user@1.2.3.4       pass jaeger2
0 jake@example.com    rsa supersecret_rsa
0 barry@narnia        rsa keys/id_narnia_rsa
```

## Test mode
* `./main.py -t --text-file input_hosts.txt -o /tmp/dump.txt`
* `./main.py -t --database-uri sqlite:////tmp/adatabase.sqlite`
* `./main.py -t --database-uri sqlite:///adatabase.sqlite -o /tmp/dump.txt`

In test mode, rather than presenting a proxy, PalladiumSquid will iterate through every set of credentials it knows,
testing each in turn. It'll try to set up each transport to a test target (example.com:80), and will rescore each
depending on success. If you're using a permanent database, this will rescore its contents, and will add and
score any new credentials if supplied in a text file. This option can be used with the output file option.

## Proxy mode

* `./main.py -p --text-file input_hosts.txt`
* `./main.py -p --text-file input_hosts.txt --database-uri sqlite:///butterybiscuitdatabase.sqlite`
* `./main.py -p --database-uri sqlite:///wowadatabase.sqlite`
* `./main.py -p --database-uri sqlite:///wowadatabase.sqlite --socks-host 12345`

Proxy mode is the main point of this to begin with. In proxy mode, the contents of the database are used to set up
rotating SSH transports behind a SOCKS5 proxy. Note that it's only SOCKS5 for now, supports all address families (ip4, 
ip6, domain), but does _not_ support anything other than TCP connect (no UDP, no TCP BIND).
