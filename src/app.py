# -*- coding: utf-8 -*-
"""
Flask application setup and routes.
"""
import logging

from authlib.integrations.flask_client import OAuth
from authlib.integrations.flask_oauth2 import ResourceProtector
from flask import Blueprint, Flask

from src import oidc

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
    return "<p>Hello, World!</p>"


@v1.route("/auth")
@require_oidc()
def auth():
    return "<p>Validation successful!</p>", 200
