#!/usr/bin/env python3

import jwt, hmac, hashlib, sys
from codecs import encode, decode


def do_help(pname):
    print(f"Usage: {pname} KEY_FILE DATA")
    sys.exit(1)


def jwt_hs256(keyfile, data):
    key = open(keyfile,'rb').read()
    header = b'{"alg":"HS256","typ":"JWT"}'
    header = encode(header,'base64').strip(b"=\n")
    payload = data.encode()
    payload = encode(payload,'base64').strip(b"=\n")
    sig = hmac.new(key, header + b'.' + payload, hashlib.sha256).digest().strip()
    sig = encode(sig, 'base64').strip(b"=\n")
    jwt = '{}.{}.{}'.format(header.decode(), payload.decode(), sig.decode())
    return jwt


if __name__ == "__main__":
    if len(sys.argv) != 3:
        do_help(sys.argv[0])

    print(jwt_hs256(sys.argv[1], sys.argv[2]))

