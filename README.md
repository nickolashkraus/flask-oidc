# Flask OIDC

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/nickolashkraus/flask-oidc/blob/master/LICENSE)
[![GitHub Actions - Python](https://github.com/nickolashkraus/flask-oidc/actions/workflows/python.yml/badge.svg)](https://github.com/nickolashkraus/flask-oidc/actions/workflows/python.yml)
[![GitHub Actions - Integration](https://github.com/nickolashkraus/flask-oidc/actions/workflows/integration.yml/badge.svg)](https://github.com/nickolashkraus/flask-oidc/actions/workflows/integration.yml)

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

**NOTE**: To build the image for x86 architectures on ARM64 (ex. Apple M1), run the following:

```bash
$ docker buildx build --platform=linux/amd64 -t nickolashkraus/flask-oidc:latest -f Dockerfile .
```

## References
* [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
* [Introduction to JSON Web Tokens](https://jwt.io/introduction)
* [JSON Web Key Sets](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets)
* [JSON Web Key Set Properties](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-set-properties)
* [Locate JSON Web Key Sets](https://auth0.com/docs/secure/tokens/json-web-tokens/locate-json-web-key-sets)
* [About security hardening with OpenID Connect](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)

## Acknowledgements

This repository relies heavily on a proof-of-concept Flask application written by Matthew Balvanz ([matthewbalvanz-wf](https://github.com/matthewbalvanz-wf)) for authenticating OIDC tokens generated by GitHub Actions.

## Example

An example of the OpenID Connect authorization code flow using GitHub's OIDC Provider is given in `.github/workflows/integration.yml.`. This GitHub Action:
1. Requests an OIDC token.
2. Makes a request to the OIDC authenticated endpoint (`/auth`).
3. Ensures validation was successful.

See the GitHub documentation for further information on using OpenID Connect within your workflows to authenticate with cloud providers:
* [Configuring OpenID Connect in cloud providers](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-cloud-providers)
