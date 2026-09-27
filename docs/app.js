/* app.js - client-side OIDC test helper for Token Studio (SPA)
 * - Builds authorization URL (supports PKCE)
 * - Performs discovery (/.well-known/openid-configuration)
 * - Exchanges code for tokens in-browser if token endpoint allows CORS
 * - Parses fragment tokens for implicit/hybrid flows
 * - Displays tokens and decodes JWT header & payload (no signature verification)
 */

function base64UrlEncode(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer);
  let str = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    str += String.fromCharCode(bytes[i]);
  }
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sha256(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return hash;
}

function generateCodeVerifier() {
  // 43-128 chars
  const array = new Uint8Array(68);
  crypto.getRandomValues(array);
  return Array.from(array).map(b => ('00' + b.toString(16)).slice(-2)).join('').slice(0,86); // hex string
}

async function createCodeChallenge(verifier) {
  const hashed = await sha256(verifier);
  return base64UrlEncode(hashed);
}

function parseQuery(qs) {
  const params = {};
  const parts = qs.replace(/^\?/, '').split('&').filter(Boolean);
  for (const p of parts) {
    const [k, ...rest] = p.split('=');
    params[decodeURIComponent(k)] = decodeURIComponent(rest.join('='));
  }
  return params;
}

function parseFragment(hash) {
  const params = {};
  const h = hash.replace(/^#/, '');
  if (!h) return params;
  h.split('&').filter(Boolean).forEach(pair => {
    const [k, ...rest] = pair.split('=');
    params[decodeURIComponent(k)] = decodeURIComponent(rest.join('='));
  });
  return params;
}

function decodeJwt(token) {
  try {
    const parts = token.split('.');
    if (parts.length < 2) return { error: 'Not a JWT' };
    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    return { header, payload };
  } catch (e) {
    return { error: e.toString() };
  }
}

async function doDiscovery(issuer) {
  const url = issuer.replace(/\/$/, '') + '/.well-known/openid-configuration';
  const res = await fetch(url);
  if (!res.ok) throw new Error('Discovery failed: ' + res.status + ' ' + res.statusText);
  return await res.json();
}

function buildAuthUrl(metadata, cfg, codeChallenge) {
  const auth = new URL(metadata.authorization_endpoint);
  auth.searchParams.set('client_id', cfg.client_id);
  auth.searchParams.set('redirect_uri', cfg.redirect_uri);
  auth.searchParams.set('response_type', cfg.response_type);
  auth.searchParams.set('scope', cfg.scope);
  if (cfg.acr_values) auth.searchParams.set('acr_values', cfg.acr_values);
  if (cfg.prompt) auth.searchParams.set('prompt', cfg.prompt);
  if (cfg.claims) auth.searchParams.set('claims', cfg.claims);

  if (cfg.extra) {
    cfg.extra.split('\n').map(l => l.trim()).filter(Boolean).forEach(line => {
      const idx = line.indexOf('=');
      if (idx > 0) {
        const k = line.slice(0, idx).trim();
        const v = line.slice(idx+1).trim();
        auth.searchParams.set(k, v);
      }
    });
  }

  if (codeChallenge) {
    auth.searchParams.set('code_challenge', codeChallenge);
    auth.searchParams.set('code_challenge_method', 'S256');
  }

  // state & nonce
  const state = Math.random().toString(36).slice(2);
  auth.searchParams.set('state', state);
  if (cfg.response_type.includes('id_token')) {
    const nonce = Math.random().toString(36).slice(2);
    auth.searchParams.set('nonce', nonce);
    sessionStorage.setItem('nonce', nonce);
  }
  sessionStorage.setItem('state', state);

  return auth.toString();
}

async function exchangeCode(metadata, cfg, code, verifier) {
  const tokenUrl = metadata.token_endpoint;
  const body = new URLSearchParams();
  body.set('grant_type', 'authorization_code');
  body.set('code', code);
  body.set('redirect_uri', cfg.redirect_uri);
  body.set('client_id', cfg.client_id);
  if (verifier) body.set('code_verifier', verifier);

  const res = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  });
  if (!res.ok) throw new Error('Token exchange failed: ' + res.status + ' ' + res.statusText);
  return await res.json();
}

// UI wiring
document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('configForm');
  const discoverySection = document.getElementById('discoveryResult');
  const discoveryJson = document.getElementById('discoveryJson');

  // Only attach the submit handler if the form exists on the page (index.html)
  if (form) {
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const data = new FormData(form);
      const cfg = {
        issuer: data.get('issuer'),
        client_id: data.get('client_id'),
        redirect_uri: data.get('redirect_uri') || (location.origin + location.pathname.replace(/\/index.html$/, '') + 'callback.html'),
        response_type: data.get('response_type') || 'code',
        scope: data.get('scope') || 'openid',
        acr_values: data.get('acr_values') || '',
        claims: data.get('claims') || '',
        prompt: data.get('prompt') || '',
        extra: data.get('extra') || '',
        pkce: data.get('pkce') === 'on'
      };

      sessionStorage.setItem('config', JSON.stringify(cfg));

      try {
        const meta = await doDiscovery(cfg.issuer);
        if (discoverySection && discoveryJson) {
          discoverySection.hidden = false;
          discoveryJson.textContent = JSON.stringify(meta, null, 2);
        }

        let codeChallenge = null;
        if (cfg.pkce && cfg.response_type.includes('code')) {
          const verifier = generateCodeVerifier();
          sessionStorage.setItem('code_verifier', verifier);
          codeChallenge = await createCodeChallenge(verifier);
        }

        const url = buildAuthUrl(meta, cfg, codeChallenge);
        // Redirect to IdP
        window.location = url;

      } catch (err) {
        alert('Error: ' + err);
        console.error(err);
      }
    });
  }

  // If we're on callback.html, handle response
  if (location.pathname.endsWith('callback.html')) {
    (async () => {
      const status = document.getElementById('status');
      const tokensSection = document.getElementById('tokens');
      const tokensContainer = document.getElementById('tokensContainer');

      const qp = parseQuery(location.search);
      const frag = parseFragment(location.hash);

      const cfg = JSON.parse(sessionStorage.getItem('config') || '{}');
      let meta = null;
      try {
        if (cfg && cfg.issuer) {
          meta = await doDiscovery(cfg.issuer);
        }
      } catch (e) {
        console.warn('Discovery on callback failed (CORS?)', e);
      }

      if (Object.keys(frag).length > 0) {
        if (status) status.textContent = 'Tokens received in fragment. Displaying.';
        if (tokensSection && tokensContainer) {
          tokensSection.hidden = false;
          displayTokens(frag, tokensContainer);
        }
      } else if (qp.code) {
        if (status) status.textContent = 'Authorization code received. Attempting in-browser exchange (requires CORS on token endpoint).';
        try {
          const verifier = sessionStorage.getItem('code_verifier');
          if (!meta) throw new Error('Discovery metadata not available; cannot exchange code.');
          const tokenResponse = await exchangeCode(meta, cfg, qp.code, verifier);
          if (status) status.textContent = 'Token exchange successful.';
          if (tokensSection && tokensContainer) {
            tokensSection.hidden = false;
            displayTokens(tokenResponse, tokensContainer);
          }
        } catch (e) {
          if (status) status.textContent = 'Token exchange failed: ' + e;
          console.error(e);
          if (tokensSection) tokensSection.hidden = true;
        }
      } else {
        if (status) status.textContent = 'No tokens or code found in the response. Check IdP configuration.';
      }

    })();
  }
});

function displayTokens(obj, container) {
  container.innerHTML = '';
  for (const [k, v] of Object.entries(obj)) {
    const section = document.createElement('section');
    section.className = 'token-block';
    const h = document.createElement('h3');
    h.textContent = k;
    section.appendChild(h);

    const pre = document.createElement('pre');
    pre.textContent = (typeof v === 'string') ? v : JSON.stringify(v, null, 2);
    section.appendChild(pre);

    if (typeof v === 'string' && v.split('.').length === 3) {
      const decoded = decodeJwt(v);
      if (!decoded.error) {
        const hdr = document.createElement('details');
        hdr.innerHTML = '<summary>Header</summary><pre>' + JSON.stringify(decoded.header, null, 2) + '</pre>';
        section.appendChild(hdr);
        const pl = document.createElement('details');
        pl.innerHTML = '<summary>Payload</summary><pre>' + JSON.stringify(decoded.payload, null, 2) + '</pre>';
        section.appendChild(pl);
      }
    }

    container.appendChild(section);
  }
}
