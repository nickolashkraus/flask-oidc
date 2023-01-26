# -*- coding: utf-8 -*-
"""
Flask application tests.
"""
import functools
import importlib
import logging
from unittest.mock import patch

from authlib.integrations import flask_oauth2
from botocore.exceptions import ClientError
from flask import Flask

from src import app, oidc

from . import utils

# A note for testing Flask applications:
#
# Typically, Flask redirects you to the canonical URL of an endpoint with a
# trailing slash, if the route has a trailing slash (ex. /projects/). This is
# not the case in testing. If the canonical URL for the endpoint has a trailing
# slash and it is not included in the request, the following HTML is returned:
#
#   <!DOCTYPE html>
#   <html lang="en">
#     <title>Redirecting...</title>
#     <h1>Redirecting...</h1>
#     <p>...</p>
#   </html>
#
# Make sure to include the canonical URL for the endpoint in the request.

class MockResourceProtector(flask_oauth2.ResourceProtector):
    """
    Mock ResourceProtector class.

    See: authlib/integrations/flask_oauth2/resource_protector.py for ResourceProtector.
    """

    # Mock __init__ method.
    def __init__(self):
        pass

    # Mock register_token_validator method.
    def register_token_validator(self, validator):
        pass

    # Mock __call__ method.
    def __call__(self, scopes=None, optional=False):
        def wrapper(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                # Comment out authentication code:
                #
                # try:
                #     self.acquire_token(scopes)
                # except MissingAuthorizationError as error:
                #     if optional:
                #         return f(*args, **kwargs)
                #     self.raise_error_response(error)
                # except OAuth2Error as error:
                #     self.raise_error_response(error)
                #
                # Add debug logging:
                logging.debug("Calling mocked ResourceProtector.")
                return f(*args, **kwargs)
            return decorated
        return wrapper


def mock_require_oidc() -> Flask:
    """
    Mock 'require_oidc' decorator and return new Flask application.

    See: src/app.py for require_oidc.
    """
    # Patch authlib `ResourceProtector` object with `MockResourceProtector`
    # object.
    patch.object(flask_oauth2, "ResourceProtector", new=MockResourceProtector).start()
    # Reload previously imported 'app' module, so that the 'require_oidc'
    # decorator uses the `MockResourceProtector` object.
    importlib.reload(app)
    # Call application factory function to generate a new application with the
    # mocked 'require_oidc' decorator.
    mock_app = app.create_app()
    mock_app.testing = True
    return mock_app


def mock_public_key() -> Flask:
    """
    Mock public key and return new Flask application.

    Instead of retrieving the public key from the JSON Web Key Set (JWKS)
    Discovery endpoint, use a preconstructed public key.

    For details on how this key was constructed, see data/README.md.
    """
    mock_public_key = patch.object(oidc, "fetch_github_oidc_public_key").start()
    mock_public_key.return_value = utils.read_public_key()
    # Reload previously imported 'app' module, so that the 'require_oidc'
    # decorator uses the mocked public key.
    importlib.reload(app)
    # Call application factory function to generate a new application with the
    # mocked 'require_oidc' decorator.
    mock_app = app.create_app()
    mock_app.testing = True
    return mock_app


def test_root_200(client):
    """
    Status: 200 OK

    Uses pytest fixture: 'client'. See: conftest.py.
    """
    resp = client.get("/v1/")
    assert b"Hello, World!" in resp.data
    assert resp.status_code == 200


# NOTE: The following tests are more instructive than functional:
#   * test_auth_401_0
#   * test_auth_401_1
#   * test_auth_401_2
#   * test_auth_401_3
def test_auth_401_0(client):
    """
    Status: 401 UNAUTHORIZED
    Error: missing_authorization

    Uses pytest fixture: 'client'. See: conftest.py.
    """
    resp = client.get("/v1/auth")
    assert b"missing_authorization" in resp.data
    assert b'Missing \\"Authorization\\" in headers.' in resp.data
    assert resp.status_code == 401


def test_auth_401_1(client):
    """
    Status: 401 UNAUTHORIZED
    Error: unsupported_token_type

    Uses pytest fixture: 'client'. See: conftest.py.
    """
    resp = client.get("/v1/auth", headers={"Authorization": "bad"})
    assert b"unsupported_token_type" in resp.data
    assert resp.status_code == 401


def test_auth_401_2():
    """
    Status: 401 UNAUTHORIZED
    Error: bad_signature

    Demonstrates a JWT with an invalid signature.

    The signature is calculated using the header and the payload, so you can
    verify that the content has not been tampered with.
    """
    mock_app = mock_public_key()
    token = utils.read_jwt("data/jwts/bad.txt")
    with mock_app.test_client() as client:
        resp = client.get("/v1/auth", headers={"Authorization": f"Bearer {token}"})
        assert b"invalid_token" in resp.data
        assert (
            b"The access token provided is expired, revoked, malformed, or "
            b"invalid for other reasons."
        ) in resp.data
        assert resp.status_code == 401


def test_auth_401_3():
    """
    Status: 401 UNAUTHORIZED
    Error: expired_token

    Demonstrates a JWT that has expired.

    The current time MUST be before the time represented by the 'exp' Claim.
    """
    mock_app = mock_public_key()
    token = utils.read_jwt("data/jwts/expired.txt")
    with mock_app.test_client() as client:
        resp = client.get("/v1/auth", headers={"Authorization": f"Bearer {token}"})
        assert b"invalid_token" in resp.data
        assert (
            b"The access token provided is expired, revoked, malformed, or "
            b"invalid for other reasons."
        ) in resp.data
        assert resp.status_code == 401


def test_auth_200():
    """
    Status: 200 OK

    Mocks the authlib library `ResourceProtector` in order to circumvent OIDC
    authentication flow.
    """
    mock_app = mock_require_oidc()
    with mock_app.test_client() as client:
        resp = client.get("/v1/auth")
        assert b"Validation successful!" in resp.data
        assert resp.status_code == 200


def test_presigned_400():
    """
    Status: 400 BAD REQUEST
    Error: Bad Request: S3 bucket and/or key not provided in request

    Mocks the authlib library `ResourceProtector` in order to circumvent OIDC
    authentication flow.
    """
    mock_app = mock_require_oidc()
    mock_generate_presigned_post = patch.object(app, "generate_presigned_post").start()
    mock_generate_presigned_post.return_value = {
        "url": "https://bucket.s3.amazonaws.com",
        "fields": {
            "acl": "public-read",
            "key": "key",
            "signature": "signature",
            "policy": "base64-encoded policy",
        },
    }
    data = {}
    with mock_app.test_client() as client:
        resp = client.post(
            "/v1/presigned", json=data, headers={"Authorization": "Bearer 1337"}
        )
        assert (
            b"Bad Request: S3 bucket and/or key not provided in request"
        ) in resp.data
        assert resp.status_code == 400


def test_presigned_500():
    """
    Status: 500 INTERNAL SERVER ERROR
    Error: Internal Server Error: An error occurred generating the presigned
           POST request.

    Mocks the authlib library `ResourceProtector` in order to circumvent OIDC
    authentication flow.
    """
    mock_app = mock_require_oidc()
    mock_generate_presigned_post = patch.object(app, "generate_presigned_post").start()
    mock_generate_presigned_post.side_effect = ClientError(
        error_response={"Error": {"Code": ""}}, operation_name=""
    )
    data = {"bucket": "bucket", "key": "key"}
    with mock_app.test_client() as client:
        resp = client.post(
            "/v1/presigned", json=data, headers={"Authorization": "Bearer 1337"}
        )
        assert (
            b"Internal Server Error: An error occurred generating the "
            b"presigned POST request"
        ) in resp.data
        assert resp.status_code == 500


def test_presigned_200():
    """
    Status: 200 OK

    Mocks the authlib library `ResourceProtector` in order to circumvent OIDC
    authentication flow.
    """
    mock_app = mock_require_oidc()
    mock_generate_presigned_post = patch.object(app, "generate_presigned_post").start()
    mock_generate_presigned_post.return_value = {
        "url": "https://bucket.s3.amazonaws.com",
        "fields": {
            "acl": "public-read",
            "key": "key",
            "signature": "signature",
            "policy": "base64-encoded policy",
        },
    }
    data = {"bucket": "bucket", "key": "key"}
    with mock_app.test_client() as client:
        resp = client.post(
            "/v1/presigned", json=data, headers={"Authorization": "Bearer 1337"}
        )
        assert b"https://bucket.s3.amazonaws.com" in resp.data
        assert resp.status_code == 200
