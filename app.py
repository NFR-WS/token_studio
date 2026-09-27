from flask import Flask, render_template, request, redirect, session, url_for, jsonify
import os
import requests
import json
import secrets
from authlib.integrations.requests_client import OAuth2Session
import jwt

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = os.environ.get('FLASK_SECRET', secrets.token_urlsafe(32))

# Helpers

def discovery(issuer):
    if issuer.endswith('/'):
        issuer = issuer[:-1]
    url = issuer + '/.well-known/openid-configuration'
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    return r.json()


def decode_jwt_no_verify(token):
    try:
        # Decode without verifying signature
        data = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
        header = jwt.get_unverified_header(token)
        return {"header": header, "payload": data}
    except Exception as e:
        return {"error": str(e)}


@app.route('/')
def index():
    # Show a form to configure OIDC settings
    return render_template('index.html')


@app.route('/start', methods=['POST'])
def start():
    form = request.form
    issuer = form.get('issuer')
    client_id = form.get('client_id')
    client_secret = form.get('client_secret') or None
    redirect_uri = form.get('redirect_uri') or (request.url_root.rstrip('/') + url_for('callback'))
    response_type = form.get('response_type') or 'code'
    response_mode = form.get('response_mode') or None
    scope = form.get('scope') or 'openid email profile'
    acr = form.get('acr_values') or None
    claims = form.get('claims') or None
    prompt = form.get('prompt') or None
    pkce = form.get('pkce') == 'on'
    extra = form.get('extra') or None

    # Save config in session for callback
    session['config'] = {
        'issuer': issuer,
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'response_type': response_type,
        'response_mode': response_mode,
        'scope': scope,
        'acr_values': acr,
        'claims': claims,
        'prompt': prompt,
        'pkce': pkce,
        'extra': extra,
    }

    # Discover provider metadata
    try:
        meta = discovery(issuer)
    except Exception as e:
        return f"Discovery failed: {e}", 400

    auth_endpoint = meta.get('authorization_endpoint')
    token_endpoint = meta.get('token_endpoint')
    session['config']['metadata'] = meta

    # Build auth request
    client = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)

    # PKCE
    code_verifier = None
    if pkce and 'code' in response_type:
        code_verifier = secrets.token_urlsafe(64)
        session['code_verifier'] = code_verifier
        # authlib expects code_challenge and method in create_authorization_url params
        code_challenge = OAuth2Session.create_s256_code_challenge(code_verifier)
    else:
        code_challenge = None

    auth_params = {}
    if acr:
        auth_params['acr_values'] = acr
    if claims:
        # Ensure valid JSON
        try:
            claims_json = json.loads(claims)
            auth_params['claims'] = json.dumps(claims_json)
        except Exception:
            # Allow string but keep as-is
            auth_params['claims'] = claims
    if prompt:
        auth_params['prompt'] = prompt
    if response_mode:
        auth_params['response_mode'] = response_mode

    # Extra params (key=value pairs, one per line)
    if extra:
        for line in extra.splitlines():
            line = line.strip()
            if not line:
                continue
            if '=' in line:
                k, v = line.split('=', 1)
                auth_params[k.strip()] = v.strip()

    # nonce for implicit/hybrid
    if 'id_token' in response_type:
        auth_params['nonce'] = secrets.token_urlsafe(16)
        session['nonce'] = auth_params['nonce']

    try:
        if code_challenge:
            uri, state = client.create_authorization_url(auth_endpoint, code_challenge=code_challenge, code_challenge_method='S256', response_type=response_type, **auth_params)
        else:
            uri, state = client.create_authorization_url(auth_endpoint, response_type=response_type, **auth_params)
    except Exception as e:
        return f"Failed to create authorization URL: {e}", 500

    session['state'] = state
    session['token_endpoint'] = token_endpoint
    session['client_id'] = client_id
    session['client_secret'] = client_secret

    # Redirect user to Authorization endpoint
    return redirect(uri)


@app.route('/callback')
def callback():
    # If response includes fragment (implicit/hybrid), browsers won't send it to server.
    # Show a small page that collects tokens from the fragment and POSTs them to /fragment
    return render_template('callback_fragment.html')


@app.route('/fragment', methods=['POST'])
def fragment_post():
    # Receive tokens posted from client-side (for implicit/hybrid flows)
    data = request.get_json() or {}
    session['tokens'] = data
    return jsonify({'status': 'ok'})


@app.route('/exchange')
def exchange():
    # Exchange code for tokens (for Authorization Code flow). This is useful in case you want a dedicated endpoint.
    config = session.get('config')
    if not config:
        return 'No config in session', 400
    token_endpoint = session.get('token_endpoint')
    client_id = session.get('client_id')
    client_secret = session.get('client_secret')
    code = request.args.get('code')
    state = request.args.get('state')
    saved_state = session.get('state')
    if state != saved_state:
        return 'Invalid state', 400

    redirect_uri = config.get('redirect_uri')
    scope = config.get('scope')
    pkce = config.get('pkce')
    code_verifier = session.get('code_verifier') if pkce else None

    client = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
    try:
        token = client.fetch_token(token_endpoint, code=code, code_verifier=code_verifier, client_secret=client_secret)
    except Exception as e:
        return f'Failed to fetch token: {e}', 500

    session['tokens'] = token
    return redirect(url_for('tokens'))


@app.route('/tokens')
def tokens():
    tokens = session.get('tokens')
    if not tokens:
        # Maybe the provider returned code to callback; try to capture from query parameters
        code = request.args.get('code')
        if code:
            # Attempt exchange inline
            return redirect(url_for('exchange', code=code, state=request.args.get('state')))
        return 'No tokens in session. Start a new flow.', 400

    # tokens can be a dict returned by fetch_token or posted from fragment
    display = {}
    for k, v in tokens.items():
        if k in ('id_token', 'access_token', 'refresh_token'):
            display[k] = {
                'raw': v
            }
            # Try to decode JWTs
            if isinstance(v, str) and (v.count('.') == 2):
                display[k]['decoded'] = decode_jwt_no_verify(v)
        else:
            display[k] = v

    return render_template('tokens.html', tokens=display)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8000)), debug=True)
