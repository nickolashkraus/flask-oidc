# -*- coding: utf-8 -*-
"""
Flask application test fixtures.

See: https://flask.palletsprojects.com/en/2.2.x/testing/
"""

import pytest

from src.app import create_app

@pytest.fixture()
def app():
    app = create_app()
    app.config.update({
        "TESTING": True,
    })
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def runner(app):
    return app.test_cli_runner()
