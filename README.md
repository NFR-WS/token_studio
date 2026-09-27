# Token Studio - OIDC test application (Flask)

This demo app helps you test OpenID Connect flows against an Identity Provider. It allows you to configure the issuer, client credentials and auth request parameters (flow, scope, acr_values, claims) and then run the authentication flow. After the flow completes the app shows raw tokens and attempts to decode JWTs (without verifying signatures) for inspection.

Features
- Configure issuer, client_id, client_secret, redirect URI, response_type, response_mode, scope, acr_values, claims, prompt, and extra params.
- Supports Authorization Code (with optional PKCE), Implicit, and Hybrid flows. For implicit/hybrid flows the client-side callback extracts tokens from the URL fragment and posts them to the server.
- Shows raw tokens and decoded JWT header/payload (no signature verification).

Security note
- This is a demo for integration testing. Do NOT use in production.
- It uses server-side in-memory sessions. Do not store real client secrets in the deployed app or commit them into git.

Quick start

1. Create a virtualenv and install dependencies:

   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt

2. Set a session secret (recommended):

   export FLASK_SECRET="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"

3. Run the app:

   python app.py

4. Open http://localhost:8000 and configure your IdP and client.

Docker

A Dockerfile is not included by default. If you want a container, I can add one.

Notes and troubleshooting
- If you want to validate id_token signatures make sure to use a proper JWT library and the provider's JWKS.
- For opaque access tokens you can configure the provider's introspection endpoint (not implemented by default) and call it to inspect opaque tokens.

License
MIT
