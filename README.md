# Unauthorize
Burp Suite extension to help identify unauthenticated access / broken access control issues 
Python/Jython Burp extension for testing whether an authenticated endpoint
remains accessible after authentication/session material is removed.

## What it does

The extension:

1. Takes an existing authenticated request.
2. Identifies common authentication/session headers.
3. Removes those headers.
4. Replays the request.
5. Compares the unauthenticated response against the original response.
6. Reports a Burp Scanner issue when access appears to remain available.
7. Searches the unauthenticated response for sensitive information.
8. Classifies findings:
   - **High**: PCI/card data, PII, passwords, secrets, API keys/tokens,
     JWTs, private keys, or other credential indicators.
   - **Medium**: file/resource exposed without authentication.
   - **Low**: other confirmed unauthenticated endpoint access.

## How to install


1. Install/configure Jython 2.7.x in Burp.
2. Go to **Extensions -> Installed -> Add**.
3. Extension type: **Python**.
4. Select `unauthorize.py`.
5. Confirm the extension loads successfully.


## How to run

### Active Scanner

Run an active scan against a target/request.

### Proxy / Repeater

Right-click an HTTP request and select Extension > Unauthorize:

`Check Unauthenticated Access`


## Authentication headers removed

The default list includes:

- Authorization
- Proxy-Authorization
- Cookie
- X-API-Key
- X-API-Token
- X-Auth-Token
- X-Access-Token
- X-Session-Token
- X-Session-ID
- X-Authentication-Token
- X-API-Auth
- API-Key
- API-Token
- Access-Token
- ID-Token
- Session
- SessionID
- Session-ID
- Auth-Token
- Authentication
- X-Authorization
- X-API-Authentication

Custom `X-Auth-*`, `X-Session-*`, `*-Auth-Token`, and `*-Access-Token`
headers are also detected.

CSRF tokens are NOT removed by default. The source has:

`REMOVE_CSRF_HEADER = False`

Set it to `True` if you explicitly want the extension to remove
`X-CSRF-Token` during the replay.


## Scope / safety

Use only against applications and systems for which you have explicit
authorization to test.
