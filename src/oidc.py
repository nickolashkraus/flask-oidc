# -*- coding: utf-8 -*-
"""
OIDC authentication.

This module is used to facilitate the authentication of an OIDC token generated
from GitHub's OIDC Provider.

GitHub Actions jobs can auto-generate an OIDC token, which can be presented to
a cloud provider that supports OIDC in order to request a short-lived access
token. This token provides access to the cloud provider without the need to
store long-lived credentials.

See:
  * https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
"""
import logging
from typing import Any, Callable

from authlib.integrations.flask_client import FlaskOAuth2App
from authlib.jose import JsonWebKey
from authlib.oauth2.rfc7523 import JWTBearerTokenValidator
from flask import g

# GitHub OpenID Provider issuer URI
# See: https://openid.net/specs/openid-connect-discovery-1_0.html#IssuerDiscovery
OPENID_ISSUER_URI = "https://token.actions.githubusercontent.com"

# GitHub OpenID Provider configuration URI
# See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
OPENID_CONFIGURATION_URI = f"{OPENID_ISSUER_URI}/.well-known/openid-configuration"


class GitHubActionsOIDCTokenValidator(JWTBearerTokenValidator):
    """
    Validates an OpenID Connect (OIDC) token from GitHub's OIDC Provider.

    GitHub's OIDC Provider configuration does not adhere to *all* of the
    required metadata specified in the the OpenID Connect 1.0 specification:
      * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata

    Authorization can, however, rely on the elements provided by the
    'claims_supported' (ex. aud, iss, sub etc.) as well as custom claims
    provided by GitHub.

    For a full list of custom claims, see the GitHub documentation:
      * https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
    """
    # TODO: Add docstring for function parameters.
    def __init__(self, public_key, issuer=None, realm=None, **extra_attributes):
        super(GitHubActionsOIDCTokenValidator, self).__init__(
            public_key, issuer, realm, **extra_attributes
        )
        # See: https://token.actions.githubusercontent.com/.well-known/openid-configuration
        self.claims_options = {
            # standard claims
            # "alg": {"essential": True},
            "aud": {"essential": True},
            # "exp": {"essential": True},
            # "iat": {"essential": True},
            # "iss": {"essential": True},
            # "jti": {"essential": True},
            # "kid": {"essential": True},
            # "nbf": {"essential": True},
            # "sub": {"essential": True},
            # "typ": {"essential": True},
            # "x5t": {"essential": True},
            # custom claims
            # "actor": {"essential": True},
            # "actor_id": {"essential": True},
            # "base_ref": {"essential": True},
            # "environment": {"essential": True},
            # "environment_node_id": {"essential": True},
            # "event_name": {"essential": True},
            # "head_ref": {"essential": True},
            # "job_workflow_ref": {"essential": True},
            # "job_workflow_sha": {"essential": True},
            # "ref": {"essential": True},
            # "ref_type": {"essential": True},
            # "repository": {"essential": True},
            # "repository_id": {"essential": True},
            # "repository_owner": {"essential": True},
            # "repository_owner_id": {"essential": True},
            # "repository_visibility": {"essential": True},
            # "run_attempt": {"essential": True},
            # "run_id": {"essential": True},
            # "run_number": {"essential": True},
            # "sha": {"essential": True},
            # "workflow": {"essential": True},
            # "workflow_ref": {"essential": True},
            # "workflow_sha": {"essential": True},
        }

    def authenticate_token(self, token_string: str) -> dict:
        """
        Validate the OIDC token.

        An OIDC token is a JSON Web Token (JWT). To validate the JWT, the JWT
        is decoded and the JWT signature is validated using the public key of
        the OIDC token provider. Next, the JWT payload is validated to ensure
        it comprises the specified claims (ex. aud, iss, sub, etc.). Custom
        claims (see: self.claims_options) are validated as well.

        It should be noted that GitHub's OIDC Provider uses RS256
        (asymmetric/public-key encryption) to create the signature for the JWT.
        RS256 generates an asymmetric signature, which means a private key must
        be used to sign the JWT and the corresponding public key must be used
        to verify the signature.

        NOTE: This method makes claims available to the application context via
        the 'g' object.

        See:
          * https://flask.palletsprojects.com/en/2.2.x/appcontext/

        :type token_string: str
        :param token_string: JSON Web Token (xxxxx.yyyyy.zzzzz)

        :rtype: dict
        :return: Dictionary of 'claims_supported'
          See: https://token.actions.githubusercontent.com/.well-known/openid-configuration
          for a list of the Claim Names.
        """
        result = super(GitHubActionsOIDCTokenValidator, self).authenticate_token(
            token_string=token_string
        )
        # Makes claims available to the application context.
        g.actions_claims = result
        return result


def fetch_github_oidc_public_key(client: FlaskOAuth2App) -> Callable:
    """
    Callable to retrieve the public key from the Authorization Server.

    This ultimately gets called during the decoding of the JWT token in
    JsonWebSignature._prepare_algorithm_key:

      if callable(key):
          key = key(header, payload)
          ...

    :type client: FlaskOAuth2App
    :param client: Flask OAuth2 Client

    :rtype: Callable
    :return: Callable for fetching GitHub's OIDC Provider public key for the
      JWT.

    Inspired by:
      * https://github.com/lepture/authlib/commit/695af265255853310c905dcd48b439955148516f#r48195848
    """
    # TODO: Add caching, since this implmentation retrieves the JWKS on every
    # invocation of client.fetch_jwk_set.
    def resolve_public_key(header: dict[str, Any], _: dict[str, Any]) -> str:
        """
        Resolve the public key used to verify the JSON Web Token (JWT).

        JSON Web Tokens can be verified using JSON Web Key Sets (JWKS), which
        is a set of keys containing the public keys used for signing RS256
        tokens.

        The public key used to sign a JWT can be located using metadata from
        the OIDC Provider configuration:

          1. Retrieve the JWKS Discovery endpoint from the OIDC Provider
             configuration ($ISSUER/.well-known/openid-configuration). This is
             specifed by 'jwks_uri':

               Example: https://token.actions.githubusercontent.com/.well-known/jwks

          2. Filter for potential signing keys (e.g., any keys missing a public
             key or with a 'kid' property). NOTE: The 'kid' property value is
             provided in the JWT header.

          3. Grab the 'kid' property from the header of the decoded JWT.

          4. Search your filtered JWKS for the key with the matching 'kid'
             property.

          5. Build a certificate using the corresponding 'x5c' property in your
             JWKS.

          6. Use the certificate to verify the JWT's signature.

        NOTE: Step 5 and 6 are completed by the authlib library.

        :type header: dict[str, Any]
        :param header: JSON Web Token (JWT) header
        :type _: dict[str, Any]
        :param _: Throwaway parameter. Required, but not used.
        """
        # The JSON Web Key Set (JWKS) is a set of keys containing the public
        # keys used to verify any JSON Web Token (JWT) issued by the
        # Authorization Server and signed using the RS256 signing algorithm.
        #
        # The JWKS endpoint is specified in the OIDC Provider configuration
        # by 'jwks_uri'.
        jwk_set = JsonWebKey.import_key_set(client.fetch_jwk_set(force=True))
        # Filter for the signing key using the 'kid' property from the header
        # of the decoded JWT. The signing key should have a matching 'kid'
        # property.
        public_key = jwk_set.find_by_kid(header.get("kid"))
        logging.debug(f"Public key {public_key}")
        return public_key

    return resolve_public_key
