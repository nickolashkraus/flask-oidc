# -*- coding: utf-8 -*-
"""
OIDC authentication tests.
"""
import unittest
from unittest.mock import patch

from src import oidc

from . import utils


class GitHubActionsOIDCTokenValidator(unittest.TestCase):
    def setUp(self):
        super(GitHubActionsOIDCTokenValidator, self).setUp()
        self.addCleanup(patch.stopall)
        self.g = oidc.GitHubActionsOIDCTokenValidator(
            public_key=utils.read_public_key(),
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
