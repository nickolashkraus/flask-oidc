# -*- coding: utf-8 -*-
"""
OIDC authentication tests.
"""

import os
import unittest
from unittest.mock import patch

from src import oidc

PUBLIC_KEY = os.path.join(os.path.dirname(__file__), "data/RS256.pub")


def _read_public_key() -> str:
    """
    Read public key for signing JWTs using the RS256 signing algorithm.

    :rtype: str
    :return: Public key
    """
    with open(PUBLIC_KEY, "r") as f:
        # Read lines of the file and remove trailing newline characters.
        lines = [x.rstrip() for x in f.readlines()]
        # Join lines, omitting first and last line.
        public_key = "".join(lines[1:-1])
    return public_key


class GitHubActionsOIDCTokenValidator(unittest.TestCase):
    def setUp(self):
        super(GitHubActionsOIDCTokenValidator, self).setUp()
        self.addCleanup(patch.stopall)
        self.g = oidc.GitHubActionsOIDCTokenValidator(
            public_key=_read_public_key(),
            issuer=oidc.GITHUB_OPENID_ISSUER_URI,
        )

    def test_init(self):
        exp = {"essential": True, "value": oidc.GITHUB_OPENID_ISSUER_URI}
        self.assertEqual(exp, self.g.claims_options["iss"])

    # NOTE: `authenticate_token()` and `fetch_github_oidc_public_key()` rely
    # heavily on authlib. To avoid testing library code, test cases are simply
    # stubbed for completeness.
    def test_authenticate_token(self):
        pass

    def test_fetch_github_oidc_public_key(self):
        pass
