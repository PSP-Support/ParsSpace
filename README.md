# Pars Space — Railway deployment bundle

This bundle is based on the real SpiderPanel backend and its API-connected dashboard, with Pars Space branding. The live `/dashboard` route serves `static/index.html`; `/spider` is a compatibility redirect to `/dashboard` (the functional UI); `preview/dashboard-review.html` is only a separate visual prototype and is **not** the production dashboard.

## Before deploying

Set these Railway Variables before the first deployment:

- `ADMIN_USERNAME`: a unique admin username (not a shared/default value).
- `ADMIN_PASSWORD`: a unique password with at least 12 characters.
- `SECRET_KEY`: a persistent random value of at least 32 characters. Generate one with `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
- `DATA_DIR=/data`.

The application intentionally refuses to start if `ADMIN_PASSWORD` or `SECRET_KEY` are missing/too short. This avoids deploying the old default `admin` password or a predictable session secret. On a fresh `/data` volume, `ADMIN_PASSWORD` is used for the initial administrator password. If you mount an existing Spider data volume, its saved password hash and saved secret are preserved for compatibility, so keep using that panel’s existing password unless you perform a deliberate credential migration.

Add a Railway Volume mounted at `/data`. The application stores its JSON state and supporting files there; without persistent storage, state can be lost when the service is replaced.

## Deploy

1. Upload/push the contents of this folder to a **new Pars Space repository** on GitHub. Do not overwrite the upstream SpiderPanel repository.
2. Create a Railway service from that repository. The included `railway.json` selects the included Dockerfile.
3. Add the Variables above and mount a Volume at `/data`.
4. Generate a Railway domain and open it. `/` redirects to `/login`; after successful login the panel opens at `/dashboard`.
5. Check `/healthz`, login/logout, inbound CRUD, user CRUD, subscriptions, backup/restore, and any integrations you rely on before migrating production traffic.

## What is included

- `main.py`: FastAPI backend and the existing Spider-compatible APIs.
- `static/index.html`: actual API-connected management UI, rebranded and restyled with a restrained black/champagne-gold glass theme.
- `static/login.html`: Pars Space login page with the cinematic pixel-art background, wired to `/api/login`.
- `static/sub.html`: subscription page served by the existing subscription routes.
- `worker/worker.js` and root `worker.js`: Cloudflare Worker code, for separate deployment.
- `preview/dashboard-review.html`: visual prototype only; it uses mock data and is not wired to production APIs.

## Cloudflare Worker

Deploy `worker/worker.js` separately to Cloudflare Workers and configure its existing KV bindings, secrets, backend URL, and routes according to your current Spider deployment. Railway does not deploy this Worker automatically.

## Important Railway limits

The FastAPI web panel can run on Railway, but deployment success does not prove every VPN/network feature is publicly reachable. Xray and MTProxy listeners, arbitrary TCP ports, Docker-dependent features, external nodes, and Cloudflare Worker/KV integration each need a real environment test. Railway's normal web domain is not a general-purpose public TCP endpoint. Do not move production traffic until the features you use have passed end-to-end tests.

## Security and operations

- Keep `SECRET_KEY` stable across deploys; changing it invalidates existing sessions.
- Keep `/data` mounted and back it up before updates.
- Do not publish Worker secrets, Telegram bot tokens, API keys, or private Reality keys.
- The old one-click upstream Spider update control is removed from the UI because it was not implemented by this backend and could have overwritten Pars Space files. Update by pushing the Pars Space repository and deploying through Railway.
- `CORS_ORIGINS` is empty by default, appropriate for a same-origin deployment. Only set explicit trusted origins if you add a separate frontend.

## Validation performed

Static checks include Python compilation, JavaScript syntax checks, HTML parsing, ZIP integrity, presence of expected routes/assets, and a check that the production page remains the API-connected Spider dashboard. No live Railway, Cloudflare KV, public TCP listener, or real traffic test has been performed from this build environment.
