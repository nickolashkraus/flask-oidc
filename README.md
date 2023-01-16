# Flask OIDC

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/nickolashkraus/flask-oidc/blob/master/LICENSE)
[![GitHub Actions - Python](https://github.com/nickolashkraus/flask-oidc/actions/workflows/python.yml/badge.svg)](https://github.com/nickolashkraus/flask-oidc/actions/workflows/python.yml)

An example Flask app that executes the OpenID Connect authorization code flow.

## Testing

```bash
pytest
```

## Development

Run the Flask development server in debug mode:

```bash
$ flask --app src/app.py --debug run
```

## References
* [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
* [Introduction to JSON Web Tokens](https://jwt.io/introduction)
* [JSON Web Key Sets](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets)
* [Locate JSON Web Key Sets](https://auth0.com/docs/secure/tokens/json-web-tokens/locate-json-web-key-sets)
* [About security hardening with OpenID Connect](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)

## Acknowledgements
This repository relies heavily on a proof-of-concept Flask application written by Matthew Balvanz ([matthewbalvanz-wf](https://github.com/matthewbalvanz-wf)) for authenticating OIDC tokens generated by GitHub Actions.
