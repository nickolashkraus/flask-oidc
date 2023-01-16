# -*- coding: utf-8 -*-
"""
Decode JWT and output its header, payload, and signature.
"""
import sys

import base64

def decode(token_string: str) -> None:
    """
    Given a well-formed JWT, output its header, payload, and signature.

    :type token_string: str
    :param token_string: JSON Web Token (xxxxx.yyyyy.zzzzz)
    """
    parts = token_string.split(".")
    header, payload, signature = parts[0], parts[1], parts[2]
    # Fix error:
    #
    #   binascii.Error: Incorrect padding
    #
    # base64.b64decode will truncate any extra padding, provided there is
    # enough in the first place. Simply add the maximum number of padding
    # characters that you would ever need, which is two (b'==') and base64
    # will truncate any unnecessary ones.
    print(base64.b64decode(header + '=='))
    print(base64.b64decode(payload + '=='))
    print(base64.b64decode(signature + '=='))

if __name__ == "__main__":
    decode(sys.argv[1])
