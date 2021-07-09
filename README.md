# revoke-back

## Configuration

The following environment variables are required:

```
JWT_PUBLIC_KEY
JWT_URL
JWT_USER
OCSP_URL
PER_PAGE
PORT
```

For testing, the following are also required:

```
TEST_OCSP_PORT
```

You can either edit `default.env`, or use a new file `custom.env` which will override `default.env`.

## Limitations

- Currently only one user is supported, configured with `JWT_USER` and `OCSP_URL`. Multiple users could be supported e.g. by mapping JWT usernames to separate OCSP responder URLs.

Before production:

- Remove ignore of JWT issuing server's certificate
- Serve HTTPS

## API specification

### `/api/v0/auth`

- Method: GET
- Headers:
    - Authorization: `Bearer <JWT>`
- Optional query strings:
    - `filter[subject]=<value>`
    - `per_page=<n>`
    - `page=<n>`

Responds with an array of certificates, as specified by query strings or otherwise all. A certificate consists of:

- `serial`: integer
- `requester`: string
- `subject`: string
- `issued`: date string (precision: day)
- `expires`: date string (precision: day)
- `revoked`: nullable date string (precision: second)

Dates are formatted according to RFC 3339.

### `/api/v0/auth/<serial>`

- Method: PUT
- Headers:
    - Authorization: `Bearer <JWT>`
- Body:
    - `revoke`: boolean

Revoke or unrevoke cert `<serial>`. Responds with a JSON body consisting of:

- `<serial>`: *status*

where *status* is "revoked", "unrevoked", or "unchanged".

### `/api/v0/login`

- Method: POST
- Headers:
    - Authorization: `Basic <Base64-encoded "user:password">`

Responds with a JSON object composed of one string-valued key `access_token`.
