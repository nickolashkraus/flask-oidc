# -*- coding: utf-8 -*-
"""
Flask application tests.
"""

# A note for testing a Flask application:
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

def test_root(client):
    resp = client.get("/v1/")
    print(resp.data)
    assert b"Hello, World!" in resp.data

