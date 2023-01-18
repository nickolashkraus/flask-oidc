# -*- coding: utf-8 -*-
"""
Flask application setup and routes.
"""
import logging
import os

import boto3
import requests
from authlib.integrations.flask_client import OAuth
from authlib.integrations.flask_oauth2 import ResourceProtector
from botocore.exceptions import ClientError
from flask import Blueprint, Flask, jsonify, request

from src import oidc

# The number of seconds the presigned POST request is valid.
EXPIRES_IN = 3600

# App setup
#
# NOTE: All code at level 0 indentation is executed when:
#   1. The source file is executed as the main program.
#   2. The file is imported from another module.
logging.basicConfig(level=logging.DEBUG)

# See: https://flask.palletsprojects.com/en/2.2.x/tutorial/views/
v1 = Blueprint("v1", __name__, url_prefix="/v1")

# Flask decorator to require OIDC. Ensures only clients with a valid OIDC token
# can access the protected API endpoint.
#
# Example:
#
#   @v1.route("/auth")
#   @require_oidc
#   def auth():
#       ...
#
require_oidc = ResourceProtector()


# See: https://flask.palletsprojects.com/en/2.2.x/patterns/appfactories/
#
# Flask will automatically detect the factory if it is named create_app or
# make_app.
def create_app():
    app = Flask(__name__)
    app.register_blueprint(v1)
    # Configure OAuth (OIDC)
    #
    # NOTE: OpenID Connect 1.0 is a identity layer on top of the OAuth 2.0
    # protocol.
    oauth = OAuth(app)
    oauth.register(name="github", server_metadata_url=oidc.OPENID_CONFIGURATION_URI)
    # Configure and register 'require_oidc' Flask decorator.
    oidc_token_validator = oidc.GitHubActionsOIDCTokenValidator(
        public_key=oidc.fetch_github_oidc_public_key(oauth.github),
        issuer=oidc.OPENID_ISSUER_URI,
    )
    require_oidc.register_token_validator(oidc_token_validator)
    return app


@v1.route("/")
def root():
    """
    A simply "Hello, World!" Flask endpoint.
    """
    return "<p>Hello, World!</p>"


@v1.route("/auth")
@require_oidc()
def auth():
    """
    An endpoint protected using OIDC authentication.

    Requests to the endpoint must contain a valid OIDC token:

      Authorization: Bearer xxxxx.yyyyy.zzzzz
    """
    return "<p>Validation successful!</p>"


@v1.route("/presigned", methods=["POST"])
# @require_oidc()
def presigned() -> (str, int):
    """
    An endpoint protected using OIDC authentication for generating a presigned
    POST request to upload an object to S3.

    A presigned URL gives you access to the object identified in the URL,
    provided that the creator of the presigned URL has permissions to access
    that object.

    This route executes the OpenID Connect authorization code flow in order to
    validate the request.

    API Reference:

      POST /presigned?demo=true
      Content-Type: application/json

      {
        "bucket": "bucket",
        "key": key
      }

    Example:

      $ http POST http://127.0.0.1:5000/v1/presigned?demo=true \
        bucket=flask-oidc key=demo.txt

    :rtype: flask.Response
    :return: Response object to return
    """
    # TODO: Use case insensitive dict.
    data = request.get_json()
    bucket, key = data.get("bucket"), data.get("key")
    if not (bucket or key):
        resp = jsonify(
            message="Bad Request: S3 bucket and/or key not provided in request"
        )
        resp.status = 400
        return resp
    try:
        resp = jsonify(generate_presigned_post(bucket=bucket, key=key))
        resp.status = 200
    except ClientError as ex:
        resp = jsonify(
            message=f"Internal Server Error: An error occurred generating the "
            f"presigned POST request:\nError: {ex}\n"
        )
        resp.status = 500
    # Example for using the presigned POST request
    if request.args.get("demo") == "true":
        # NOTE: The generated presigned URL includes both a URL and additional
        # fields that must be passed as part of the subsequent HTTP POST
        # request.
        url = resp.get_json().get("url")
        data = resp.get_json().get("fields")
        filename = os.path.join(os.path.dirname(__file__), "demo.txt")
        with open(filename, "rb") as f:
            # 'files' is a dictionary of {'name': file-tuple} where
            # 'file-tuple' is a 2-tuple ('filename', fileobj).
            #
            # See: https://requests.readthedocs.io/en/latest/api/#requests.request
            files = {"file": ("demo.txt", f)}
            r = requests.post(url=url, data=data, files=files)
            r.raise_for_status()
    return resp


def generate_presigned_post(bucket: str, key: str) -> dict:
    """
    Generate a presigned POST request to upload an object to S3.

    Example:

      {
        "url": "https://bucket.s3.amazonaws.com",
        "fields": {
          "acl": "public-read",
          "key": "key",
          "signature": "signature",
          "policy": "base64-encoded policy"
        }
      }

    See: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html?highlight=presigned#S3.Client.generate_presigned_post

    :type bucket: str
    :param bucket: Name of the S3 bucket.
    :type key: str
    :param key: Name of the S3 object key.

    :rtype: dict
    :return: Dictionary with two keys: "url" and "fields".
      "url" is the URL to post to. "fields" is a dictionary filled with the
      form fields and respective values to use when submitting the POST request
      to upload the object to S3. See above example.
    """
    s3_client = boto3.client("s3")
    try:
        resp = s3_client.generate_presigned_post(
            Bucket=bucket, Key=key, ExpiresIn=EXPIRES_IN
        )
    except ClientError:
        raise
    return resp
