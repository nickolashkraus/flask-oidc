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
    #
    # Fix error:
    #
    #   binascii.Error: Invalid base64-encoded string: number of data
    #   characters (333) cannot be 1 more than a multiple of 4
    #
    # Pad bytes such that length is a multiple of 4.
    print(base64.b64decode(pad(header)))
    print(base64.b64decode(pad(payload)))
    print(base64.b64decode(pad(signature)))

def pad(b: bytes) -> bytes:
    """
    Pad bytes such that length is a multiple of 4.
    """
    x = len(b) % 4
    if x > 0:
        return b + '=' * (4 - x) + '===='
    else:
        return b

if __name__ == "__main__":
    decode(sys.argv[1])
