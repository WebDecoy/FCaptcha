# FCaptcha Installation Guide

This guide covers installing and deploying FCaptcha for development and production environments.

## Table of Contents

- [Requirements](#requirements)
- [Quick Start (Development)](#quick-start-development)
- [Server Installation](#server-installation)
  - [Node.js](#nodejs-server)
  - [Python](#python-server)
  - [Go](#go-server)
- [Docker Deployment](#docker-deployment)
- [Production Setup](#production-setup)
- [Configuration Reference](#configuration-reference)
- [Upgrading to 1.23.0](#upgrading-to-1230)
- [Upgrading to 1.22.0](#upgrading-to-1220)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

---

## Requirements

### Server Requirements

| Language | Version | Notes |
|----------|---------|-------|
| Node.js | 18+ | Recommended: 20 LTS |
| Python | 3.10+ | Recommended: 3.12 |
| Go | 1.24+ | Required for native JA4 support |

### Optional

- **Docker** - For containerized deployment
- **Nginx/Caddy** - For reverse proxy and TLS termination

---

## Quick Start (Development)

Get FCaptcha running in under 2 minutes:

```bash
# Clone the repository
git clone https://github.com/yourusername/fcaptcha.git
cd fcaptcha

# Start the Node.js server (easiest)
cd server-node
npm install
FCAPTCHA_SECRET=local-development-secret node server.js

# Server is now running at http://localhost:3000
```

Open `demo/index.html` in your browser to test.

---

## How the widget reaches the browser

FCaptcha ships in two halves: an HTTP API (`server-node`, `server-python`, `server-go`) and a browser widget (`client/fcaptcha.js`).

**By default, `server-node` serves the widget at `/fcaptcha.js` from the same origin as the API.** Integrators that expose a single `serverUrl` to their clients (and load the widget from `<serverUrl>/fcaptcha.js`) work out of the box. Most consumers want this.

If you'd rather host the widget on a CDN or edge cache and only run the API from the FCaptcha server, set `FCAPTCHA_SERVE_CLIENT=false` and serve `client/fcaptcha.js` yourself from wherever fits your infrastructure. Point your widget loader at that URL.

If you've copied `server-node/` to a location where the sibling `client/` directory isn't present, set `FCAPTCHA_CLIENT_PATH=/absolute/path/to/fcaptcha.js` to override the default lookup.

The Go server (`server-go`) already serves `/fcaptcha.js` via its embedded static directory. The Python server (`server-python`) does not yet — track [issue #4](https://github.com/WebDecoy/FCaptcha/issues/4) for parity.

---

## Server Installation

### Node.js Server

**Step 1: Install dependencies**

```bash
cd server-node
npm install
```

**Step 2: Configure environment**

```bash
# Create .env file (optional)
echo "FCAPTCHA_SECRET=your-secret-key-here" > .env
echo "PORT=3000" >> .env
```

Or set environment variables directly:

```bash
export FCAPTCHA_SECRET=your-secret-key-here
export PORT=3000
```

**Step 3: Start the server**

```bash
# Development
node server.js

# Production (with PM2)
npm install -g pm2
pm2 start server.js --name fcaptcha
pm2 save
```

**Step 4: Verify**

```bash
curl http://localhost:3000/health
# {"status":"ok"}
```

---

### Python Server

**Step 1: Create virtual environment (recommended)**

```bash
cd server-python
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows
```

**Step 2: Install dependencies**

```bash
pip install -r requirements.txt
```

**Step 3: Configure environment**

```bash
export FCAPTCHA_SECRET=your-secret-key-here
export PORT=3000
```

**Step 4: Start the server**

```bash
# Development
python server.py

# Or with uvicorn directly — note --no-proxy-headers
uvicorn server:app --host 0.0.0.0 --port 3000 --no-proxy-headers

# Production (with gunicorn)
pip install gunicorn
gunicorn server:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:3000 \
  --forwarded-allow-ips=""
```

> **Why `--no-proxy-headers`.** uvicorn does its own `X-Forwarded-For`
> resolution by default, rewriting `request.client` from the header whenever the
> real peer is loopback. FCaptcha then sees the *claimed* address where it
> expects the socket peer, and its own trusted-proxy logic ends up checking the
> visitor's IP against the proxy allowlist. Behind a same-host reverse proxy
> that means every request is logged as coming from an untrusted peer and picks
> up a spurious detection. Let `TRUSTED_PROXIES` be the only thing that decides
> which peers may speak for a client. `python server.py` sets this for you.

**Step 5: Verify**

```bash
curl http://localhost:3000/health
# {"status":"ok"}

# The browser widget is served from the same origin by default:
curl -I http://localhost:3000/fcaptcha.js
# HTTP/1.1 200 OK
```

By default, `server-python` serves `client/fcaptcha.js` at `/fcaptcha.js` so integrators that expose a single `serverUrl` to their clients (and load the widget from `<serverUrl>/fcaptcha.js`) work out of the box. Set `FCAPTCHA_SERVE_CLIENT=false` to opt out (e.g. when hosting the widget on a CDN), or `FCAPTCHA_CLIENT_PATH=/abs/path/to/fcaptcha.js` to override the default lookup when `server-python/` is deployed without the sibling `client/` directory.

---

### Go Server

**Step 1: Build the binary**

```bash
cd server-go
go build -o fcaptcha-server .
```

**Step 2: Configure environment**

```bash
export FCAPTCHA_SECRET=your-secret-key-here
export PORT=3000
```

**Step 3: Run the server**

```bash
./fcaptcha-server
```

**Step 4: Verify**

```bash
curl http://localhost:3000/health
# {"status":"ok"}
```

---

## Docker Deployment

### Single Container

**Node.js**

```bash
cd server-node
docker build -t fcaptcha-node .
docker run -d \
  --name fcaptcha \
  -p 3000:3000 \
  -e FCAPTCHA_SECRET=your-secret-key-here \
  fcaptcha-node
```

**Python**

```bash
cd server-python
docker build -t fcaptcha-python .
docker run -d \
  --name fcaptcha \
  -p 3000:3000 \
  -e FCAPTCHA_SECRET=your-secret-key-here \
  fcaptcha-python
```

**Go**

```bash
cd server-go
docker build -t fcaptcha-go .
docker run -d \
  --name fcaptcha \
  -p 3000:3000 \
  -e FCAPTCHA_SECRET=your-secret-key-here \
  fcaptcha-go
```

### Docker Compose (single instance)

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  fcaptcha:
    build: ./server-node  # or server-python, server-go
    ports:
      - "3000:3000"
    environment:
      - FCAPTCHA_SECRET=your-secret-key-here
    restart: unless-stopped
```

FCaptcha state is process-local. `REDIS_URL` is reserved but currently unused,
so run a single instance until the distributed-state backend is implemented.

Run:

```bash
docker-compose up -d
```

---

## Production Setup

### 1. Generate a Strong Secret

```bash
# Generate a 32-character random secret
openssl rand -hex 32
# Example output: a1b2c3d4e5f6...

export FCAPTCHA_SECRET=a1b2c3d4e5f6...
```

### 2. Reverse Proxy with Nginx

```nginx
# /etc/nginx/sites-available/fcaptcha
server {
    listen 80;
    server_name captcha.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name captcha.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/captcha.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/captcha.yourdomain.com/privkey.pem;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }

    # Cache static assets
    location /fcaptcha.js {
        proxy_pass http://127.0.0.1:3000;
        proxy_cache_valid 200 1h;
        add_header Cache-Control "public, max-age=3600";
    }
}
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/fcaptcha /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

This layout needs no `TRUSTED_PROXIES` setting: nginx reaches FCaptcha over
`127.0.0.1`, which is trusted by default, so the `X-Real-IP` it sets is honoured.
Make sure FCaptcha itself only listens on loopback — if port 3000 is also
reachable from the internet, callers bypass nginx and set that header
themselves. See [Trusted proxies](#trusted-proxies).

### 3. Reverse Proxy with Caddy (Simpler)

```bash
# /etc/caddy/Caddyfile
captcha.yourdomain.com {
    reverse_proxy localhost:3000

    header {
        X-Frame-Options "SAMEORIGIN"
        X-Content-Type-Options "nosniff"
    }
}
```

### 4. Systemd Service (Linux)

Create `/etc/systemd/system/fcaptcha.service`:

```ini
[Unit]
Description=FCaptcha Server
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/fcaptcha/server-node
Environment=NODE_ENV=production
Environment=FCAPTCHA_SECRET=your-secret-key-here
Environment=PORT=3000
ExecStart=/usr/bin/node server.js
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable fcaptcha
sudo systemctl start fcaptcha
sudo systemctl status fcaptcha
```

### 5. Multiple Instances (Load Balancing)

For high availability, run multiple instances behind a load balancer:

```nginx
upstream fcaptcha_backend {
    least_conn;
    server 127.0.0.1:3001;
    server 127.0.0.1:3002;
    server 127.0.0.1:3003;
}

server {
    listen 443 ssl http2;
    server_name captcha.yourdomain.com;

    location / {
        proxy_pass http://fcaptcha_backend;
        # ... other proxy settings
    }
}
```

**Important:** Do not run multiple instances yet. Server state is process-local;
Redis-backed shared state is planned but not implemented.

---

## Configuration Reference

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `FCAPTCHA_SECRET` | Yes | - | Secret key for signing tokens (min 16 chars) |
| `FCAPTCHA_INSECURE_DEV_MODE` | No | off | Explicitly use the public development signing key for local-only development. Never expose a server with this enabled |
| `FCAPTCHA_VERIFY_SECRET` | No | `FCAPTCHA_SECRET` | Credential your backend sends as `secret` when verifying a token. Split it from the signing key so a leaked verify credential cannot also mint tokens |
| `FCAPTCHA_LEGACY_UNAUTH_VERIFY` | No | off | Restore the pre-1.22.0 behaviour where token verification accepted any caller. Migration cover for one release — see [Upgrading to 1.22.0](#upgrading-to-1220) |
| `FCAPTCHA_ALLOWED_HOSTNAMES` | No | (any) | Comma-separated hostnames permitted to mint tokens, matched against the request `Origin` (then `Referer`) |
| `PORT` | No | 3000 | Server port |
| `REDIS_URL` | No | - | Reserved; distributed state is not implemented yet |
| `NODE_ENV` | No | development | Set to `production` for Node.js |
| `TRUSTED_PROXIES` | No | loopback + private ranges | Peers allowed to set `X-Forwarded-For` / `X-Real-IP` / TLS-fingerprint headers. See [Trusted proxies](#trusted-proxies) |

### Trusted proxies

Every IP-derived check — datacenter ranges, Tor/VPN, rate limiting, token IP
binding, PoW difficulty — is only as good as the address the server is handed.
`X-Forwarded-For` and `X-Real-IP` are set by whoever opened the connection, so
FCaptcha reads them **only when the peer is in `TRUSTED_PROXIES`**. Any other
caller is attributed to its socket address, and a forged header is ignored.

`TRUSTED_PROXIES` takes a comma-separated list of CIDRs and bare IPs:

| Value | Meaning |
|-------|---------|
| *unset* | Loopback plus the private and link-local ranges (`127.0.0.0/8`, `::1/128`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `fe80::/10`, `fc00::/7`) |
| `10.0.0.0/8,203.0.113.7` | Only these peers |
| `*` | Every peer. Correct **only** when an edge you control always overwrites the headers — otherwise this restores the spoofing bypass |
| `none` (or empty) | No peer; always use the socket address |

The default covers the usual setups — nginx on `127.0.0.1`, a sidecar proxy, an
in-cluster ingress, Railway, Fly — with no configuration. Set it explicitly when
your proxy reaches FCaptcha from a public address (for example a Cloudflare
Tunnel or a load balancer in another VPC), and list only that proxy's ranges.

The server logs the resolved set on startup:

```
Trusted proxies: 127.0.0.0/8, ::1/128, 10.0.0.0/8, ...
```

If FCaptcha is reachable directly as well as through your proxy, restrict it at
the firewall — a trusted-proxy list cannot help if an attacker can connect from
inside a trusted range.

### Checking your deployment

The failure to watch for is not a bypass — it is the quiet opposite. If your
reverse proxy's address is *not* in the trust set, FCaptcha ignores the
`X-Real-IP` it sets and attributes **every visitor to the proxy**. Rate limiting
then throttles all traffic as one client and IP reputation becomes meaningless.

FCaptcha logs this the first time it happens, naming the address to add:

```
warning: ignoring forwarding headers from untrusted peer 100.64.3.7. If that is
your reverse proxy, add it to TRUSTED_PROXIES — until then every visitor is
attributed to 100.64.3.7. If not, a client is spoofing them and they are
correctly ignored.
```

Check the logs after deploying. If that warning names your proxy, add its range.
If it names random internet addresses, that is spoofing being correctly blocked.

**Docker.** Three cases, measured:

| Setup | Peer the container sees | Result |
|-------|-------------------------|--------|
| Proxy container on the same compose network | its bridge address, e.g. `172.17.0.4` | inside `172.16.0.0/12`, trusted — works with no config |
| Published port on Docker Desktop (macOS/Windows) | the VM gateway, `192.168.65.1` | inside `192.168.0.0/16`, so **trusted** |
| Published port on Linux | Docker's DNAT normally preserves the caller's real address | public callers are untrusted, as intended |

The middle row is the one to watch. Docker Desktop NATs published-port traffic
through its VM gateway, so **every** caller arrives from a private, trusted
address and can forge forwarding headers. That is harmless for local
development, but if you ever expose such a port to the internet, turn the
default off:

```bash
docker run -p 3000:3000 -e TRUSTED_PROXIES=none ghcr.io/webdecoy/fcaptcha
```

Do not infer your own case from this table — confirm it. Start the container,
send a request, and read the log line it prints:

```bash
docker logs <container> | grep -E 'trusted proxies|from '
```

The request log shows the peer address the server actually saw. If that address
is inside the trust set and is *not* your reverse proxy, forwarding headers are
forgeable and you want `TRUSTED_PROXIES=none`.

**PaaS (Railway, Fly, Render, Heroku).** These route through an edge proxy whose
address is often **outside** RFC 1918. Railway's, for example, is in the RFC 6598
carrier-grade NAT block — observed peers are `100.64.0.x`. The defaults will not
cover it, so set it explicitly:

```bash
TRUSTED_PROXIES=100.64.0.0/10   # Railway
```

Railway's own guidance says only "the `100.0.0.0/8` range", which is looser than
what it actually uses and would trust ~64 million publicly-routable addresses.
`100.64.0.0/10` is the real CGNAT block and is the safer setting; if the warning
above ever names a `100.x` peer outside it, widen to `100.0.0.0/8`.

This is safe on a PaaS precisely because the container is not directly
reachable: the platform's proxy is the only possible peer. Confirm against the
startup log and the warning above rather than assuming.

### PoW Difficulty Levels

| Difficulty | Approx. Time | When Used |
|------------|--------------|-----------|
| 4 | 100-500ms | Default for all requests |
| 5 | 500ms-3s | Datacenter IPs |
| 6 | 2-10s | Rate-limited IPs |

### Score Thresholds

| Score Range | Recommendation | Typical Action |
|-------------|----------------|----------------|
| 0.0 - 0.3 | Allow | Proceed normally |
| 0.3 - 0.5 | Allow | Log for monitoring |
| 0.5 - 0.7 | Challenge | Show additional verification |
| 0.7 - 1.0 | Block | Reject request |

---

## Upgrading to 1.23.0

**A proof of work is now required for a token.** `/api/verify` and `/api/score`
withhold the token when the request carries no valid PoW solution, instead of
merely scoring it.

If you use the bundled widget, nothing changes — it already solves a challenge on
every path and aborts rather than submit without one. Verified against the
measurement harness: human false-positive rate stays 0.00% and the human median
score is unchanged at 0.097.

If you call `/api/verify` directly from your own client, you must now complete
the handshake: `GET /api/pow/challenge`, echo the returned nonce in
`signals.meta.challengeNonce`, commit the signals into the PoW input, and send
the solution as `powSolution`. A refusal reports `"reason": "pow_not_satisfied"`.

Why: the final score is a weighted sum, so the `bot` category could contribute at
most its 0.13 weight against a 0.5 threshold. Every PoW failure firing at once
reached 0.1298 — so a bare `curl` with no solution and no signals was issued a
valid token. There is no configuration to restore the old behaviour; it was a
bypass, not a feature.

## Upgrading to 1.22.0

Two changes need action before you deploy.

**1. Token verification now requires the secret.**

`POST /api/token/verify` used to accept the `secret` parameter and ignore it, so
any caller who could reach the endpoint could spend a token. It is now checked.
If your backend already sends `secret` (as the README has always shown), nothing
changes. If it does not, either add it:

```diff
  POST /api/token/verify
- {"token": "..."}
+ {"token": "...", "secret": "<FCAPTCHA_SECRET>"}
```

or set `FCAPTCHA_LEGACY_UNAUTH_VERIFY=true` to keep the old behaviour for one
release while you update. A wrong or missing secret answers `401`.

**2. The token format is now identical across the three servers.**

Go emitted padded base64url, Node unpadded, and Python signed a payload with
different JSON spacing — so no two implementations could verify each other's
tokens. This went unnoticed because each server only ever verified its own. All
three now emit unpadded base64url over a compact, sorted-key payload, and all
three accept the old encodings, so a rolling deploy is safe and tokens in flight
keep working.

This only mattered if you ran a **mixed fleet** (say Go and Node behind one load
balancer) or migrated between implementations; in that setup verification was
failing intermittently before and works now.

## Verification

### Run the Test Suite

```bash
# Make sure server is running first
cd /path/to/fcaptcha
node test/test-detection.js

# Expected output:
# FCaptcha Detection Test Suite
# Testing against: http://localhost:3000
# ...
# Passed: 50
# Failed: 0
# All tests passed!
```

### Manual API Tests

```bash
# Health check
curl http://localhost:3000/health

# Get PoW challenge
curl "http://localhost:3000/api/pow/challenge?siteKey=test"

# Verify (will fail without valid signals, but confirms endpoint works)
curl -X POST http://localhost:3000/api/verify \
  -H "Content-Type: application/json" \
  -d '{"siteKey":"test","signals":{}}'
```

### Browser Test

1. Open `demo/index.html` in a browser
2. Click the checkbox
3. Should show green checkmark when verified

---

## Troubleshooting

### Server won't start

**Port already in use:**
```bash
# Find what's using the port
lsof -i :3000
# Kill it or use a different port
export PORT=3001
```

**Missing dependencies:**
```bash
# Node.js
rm -rf node_modules && npm install

# Python
pip install -r requirements.txt --force-reinstall

# Go
go mod tidy
```

### CORS errors in browser

Make sure your frontend is calling the correct server URL:
```javascript
FCaptcha.serverUrl = 'http://localhost:3000';  // Development
FCaptcha.serverUrl = 'https://captcha.yourdomain.com';  // Production
```

### Token verification failing

1. Check that `FCAPTCHA_SECRET` is the same on all servers
2. Tokens expire after 5 minutes - verify within that window
3. Each token can only be verified once

### High scores for legitimate users

Check the detection details in the response:
```bash
curl -X POST http://localhost:3000/api/verify \
  -H "Content-Type: application/json" \
  -d '{"siteKey":"test","signals":{}}' | jq '.detections'
```

Common causes:
- Missing PoW solution (client not sending it)
- VPN/datacenter IP addresses
- Browser privacy extensions blocking fingerprinting

### PoW taking too long

On slower devices, PoW may take longer. The difficulty auto-scales, but you can adjust thresholds in the server code if needed.

---

## Next Steps

- Read [ARCHITECTURE.md](ARCHITECTURE.md) for technical details
- Check the [README.md](README.md) for integration examples
- Run `node test/test-detection.js` to verify your setup

---

## Support

- GitHub Issues: [github.com/yourusername/fcaptcha/issues](https://github.com/yourusername/fcaptcha/issues)
- Documentation: [README.md](README.md)
