# -*- coding: utf-8 -*-
"""
Utility functions.
"""
import os


def read_public_key() -> str:
    """
    Read the public key used for signing JWTs.

    :rtype: str
    :return: Public key (in PEM format).
    """
    PUBLIC_KEY = os.path.join(os.path.dirname(__file__), "data/RS256.pem")
    with open(PUBLIC_KEY, "r") as f:
        public_key = f.read()
    return public_key


def read_jwt(filename: str) -> str:
    """
    Read JWT by filename.

    :type filename: str
    :param filename: Relative filename for the JWT.
      Ex: data/jwts/expired.txt

    :rtype: str
    :return: JWT
    """
    JWT = os.path.join(os.path.dirname(__file__), filename)
    with open(JWT, "r") as f:
        # Read lines of the file and remove trailing newline characters.
        lines = [x.rstrip() for x in f.readlines()]
        # Join lines
        jwt = "".join(lines)
    return jwt
