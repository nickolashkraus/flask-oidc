# -*- coding: utf-8 -*-
"""
Flask application.
"""
from flask import Flask, Blueprint

# See: https://flask.palletsprojects.com/en/2.2.x/tutorial/views
v1 = Blueprint("v1", __name__, url_prefix="/v1")


# See: https://flask.palletsprojects.com/en/2.2.x/patterns/appfactories
#
# Flask will automatically detect the factory if it is named create_app or
# make_app in hello.
def create_app():
    app = Flask(__name__)
    app.register_blueprint(v1)

    return app

@v1.route("/")
def root():
    return "<p>Hello, World!</p>"
