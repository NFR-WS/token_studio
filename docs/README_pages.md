# GitHub Pages (SPA) — Token Studio

This folder contains a static single-page application version of Token Studio that can be hosted on GitHub Pages.

How to publish to GitHub Pages (project site)
1. Files are in the `docs/` directory on the `main` branch. GitHub Pages can serve this directory directly.
2. In your repository settings -> Pages: choose "Branch: main" and "Folder: /docs" and save. GitHub will publish the site to:
   https://<your-username>.github.io/token_studio/

Register redirect URI in your IdP
- The SPA callback page URL is:
  https://<your-username>.github.io/token_studio/callback.html
- Register that exact URL in your OIDC client configuration (redirect URI).

Notes / limitations
- The SPA attempts to do discovery (/.well-known/openid-configuration) and, for Authorization Code flows, will attempt to exchange the code for tokens using the provider's token endpoint via a fetch POST. For that exchange to work in-browser the token endpoint must allow CORS (Access-Control-Allow-Origin) from the GitHub Pages origin. Many IdPs do NOT allow this for security reasons.
- If the token endpoint does not allow CORS you have two choices:
  - Use implicit (tokens in fragment) or hybrid flows where tokens are returned directly to the browser in the redirect. This is less recommended for security.
  - Deploy the original Flask server (or another backend) and keep sensitive exchanges server-side.

Security reminders
- This SPA stores only ephemeral PKCE verifiers and state in sessionStorage. Do not use this for production.
- Use HTTPS and register the correct redirect URI in your IdP.

If you want, I can:
- Publish the SPA to the gh-pages branch automatically using a GitHub Action, and/or
- Add a small server-side proxy to perform the token exchange when the provider blocks CORS.

