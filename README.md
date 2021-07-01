## API specification

### `/api/v0/noauth`

- Method: GET
- Optional query strings:
    - filter[subject]=<value>
    - per_page=<n>
    - page=<n>

Responds with array of certificates, as specified by query strings or otherwise all. A certificate consists of:

- serial: integer
- requester: string
- subject: string
- issued: date string
- expires: date string
- revoked: date string or `null`

Dates are formatted "YYYY-MM-DD".

### `/api/v0/noauth/<serial>`

- Method: PUT
- Body:
    - revoke: boolean

Revoke or unrevoke cert `<serial>`. Responds with a JSON body consisting of:

- `<serial>`: *status*

where *status* is "revoked", "unrevoked", or "unchanged".
