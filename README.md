# PhishGuard Node API

Node.js and Express port of the active Python API. Data is stored in SQLite at `./data/phishguard.sqlite` by default. Node 22.13 or newer is required because the API uses Node's built-in `node:sqlite` module.

## Setup

1. Copy `.env.example` to `.env` and set the credentials for integrations you want to enable.
2. Run `npm install`.
3. Run `npm start` (or `npm run dev` while developing), or start the PM2 process with `npm run pm2:start`.

The API listens on port 7779 by default. Set `PORT` and `SQLITE_PATH` to change the port and database file. GROQ, VirusTotal, WhatsApp, and n8n credentials are optional. WhatsApp accepts `WHATSAPP_PERMANENT_TOKEN` (or the access-token aliases) and defaults to Graph API v20.0, following the printer app's WhatsApp service. Set `FB_APP_SECRET` to validate Meta's `X-Hub-Signature-256` webhook signature; this is required when `NODE_ENV=production`. WhatsApp and n8n features require their matching credentials.

## Endpoints

- `GET /` and `GET /health`
- `POST /scan-url` with `{ "url": "https://example.com" }`; add `?rescan=true` to bypass the saved-result cache.
- `GET /dashboard/summary`
- `GET` and `POST /webhook/whatsapp`; POST acknowledges quickly, deduplicates inbound message IDs, and records `sent`, `delivered`, `read`, and `failed` status callbacks.
- `POST /n8n/whatsapp` with `{ "sender": "...", "text": "...", "message_id": "..." }` and `X-N8N-Secret`; returns a `reply` string for n8n to send back to the sender.

The OpenAPI request/response contract is in `n8n/whatsapp-api.openapi.json`. An importable n8n workflow is in `n8n/whatsapp-to-phishguard.workflow.json`; import it, select your WhatsApp Trigger OAuth credential, replace the Node API URL if n8n is on another host, and replace the two HTTP credential placeholders. The workflow's WhatsApp Trigger receives Meta message events, maps the text sender, calls the Node API, and sends the returned reply through WhatsApp Cloud API. Use the Node API's reachable host in n8n; `localhost` only works if n8n runs on the same host/network namespace.

PM2 configuration is in `ecosystem.config.cjs`; use `npm run pm2:start`, `npm run pm2:restart`, and `npm run pm2:stop`. Keep `.env` private and out of Git.

Tables for users, URL scans, WhatsApp conversation state, and conversation history are initialized on startup. Password and token settings are retained in the environment contract for compatibility; the former Python auth route modules were empty and were not mounted by its API entrypoint.

The WhatsApp sender uses Meta's versioned `/{PHONE_NUMBER_ID}/messages` endpoint with a bearer token and typed text payload. `sendWhatsAppTemplate` is available for approved templates such as `hello_world`; outside the customer support window, WhatsApp requires a template instead of a free-form text reply. A successful API response means Meta accepted the message. Delivery or failure is confirmed later by a `statuses` webhook, so subscribe the app to the WhatsApp Business Account's `messages` webhook field.

The URL detector carries over the Python rule-based checks and VirusTotal lookup/submission. The Python scikit-learn pickle model is not executable in Node, so this API reports that model predictions are unavailable and does not claim equivalent ML results.

## Environment checks

Run `npm test` for the environment variable validation checks.
