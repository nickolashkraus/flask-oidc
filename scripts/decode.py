# -*- coding: utf-8 -*-
"""
Decode a JWT and output its header, payload, and signature.
"""
import base64
import sys


def decode(token_string: str) -> None:
    """
    Given a well-formed JWT, output its header, payload, and signature.

    :type token_string: str
    :param token_string: JSON Web Token (xxxxx.yyyyy.zzzzz)

    Side Effect: Outputs header, payload, and signature to standard output.
    """
    parts = token_string.split(".")
    header, payload, signature = parts[0], parts[1], parts[2]
    print(f"Header: {header}\nPayload: {payload}\nSignature: {signature}")
    for x in [header, payload]:
        try:
            # NOTE: The header and payload of the JWT are base64url encoded.
            print(base64.urlsafe_b64decode(pad(x)))
        except Exception as ex:
            print(
                f"An error occurred decoding the following string: {signature}\nError: {ex}\n"
            )
    # NOTE: The signature of the JWT is NOT base64 encoded!
    #
    #   HMACSHA256(
    #     base64UrlEncode(header) + "." +
    #     base64UrlEncode(payload),
    #     secret)
    #
    # See: https://jwt.io/introduction
    print(signature)


def pad(s: str) -> str:
    """
    Pad a base64-encoded string such that its length is a multiple of 4.

    Fixes error:

      binascii.Error: Incorrect padding

    base64.b64decode will truncate any extra padding, provided there is
    enough in the first place. Simply add the maximum number of padding
    characters that you would ever need, which is two (b'==') and base64
    will truncate any unnecessary ones.

    Fixes error:

      binascii.Error: Invalid base64-encoded string: number of data
      characters (xxx) cannot be x more than a multiple of 4

    :type s: str
    :param s: base64-encoded string

    :rtype: str
    :return: padded base64-encoded string
    """
    x = len(s) % 4
    if x > 0:
        # Pad string such that its length is a multiple of 4.
        return s + "=" * (4 - x)
    else:
        return s


if __name__ == "__main__":
    decode(sys.argv[1])
