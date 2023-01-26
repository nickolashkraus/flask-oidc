# Test Data

## `RS256.pem`

**Description**: One of two public keys used to sign JWTs issued by GitHub's OIDC Provider. See: GitHub's JSON Web Key Set (JWKS) endpoint (`jwks_uri`):
  * https://token.actions.githubusercontent.com/.well-known/jwks

The public key is taken from the `x5c` property of the JSON Web Key:

```bash
X5C="<value>"
echo "${X5C}" | base64 --decode > x5c.der
openssl x509 -in x5c.der -inform DER -text
```

## `jwts/bad.txt`

**Description**: A RS256 JWT from GitHub Actions with the last character changed (`w` -> `W`), thereby invalidating the token signature.

## `jwts/default.txt`

**Description**: Default RS256 JWT from [jwt.io Debugger](https://jwt.io/#debugger-io).

## `jwts/expired.txt`

**Description**: Expired RS256 JWT from GitHub Actions.

The JWT was retrieved using the following command:
```bash
OIDC_TOKEN=$(curl -sSL "${ACTIONS_ID_TOKEN_REQUEST_URL}" \
  -H "Accept: application/json; api-version=2.0" \
  -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "User-Agent: actions/oidc-client" \
  --data "{}" | jq -r ".value")
```
