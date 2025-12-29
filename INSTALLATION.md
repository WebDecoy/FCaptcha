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
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

---

## Requirements

### Server Requirements

| Language | Version | Notes |
|----------|---------|-------|
| Node.js | 18+ | Recommended: 20 LTS |
| Python | 3.10+ | Recommended: 3.12 |
| Go | 1.21+ | Recommended: 1.22 |

### Optional

- **Redis** - For distributed state in multi-instance deployments
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
node server.js

# Server is now running at http://localhost:3000
```

Open `demo/index.html` in your browser to test.

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

# Or with uvicorn directly
uvicorn server:app --host 0.0.0.0 --port 3000

# Production (with gunicorn)
pip install gunicorn
gunicorn server:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:3000
```

**Step 5: Verify**

```bash
curl http://localhost:3000/health
# {"status":"ok"}
```

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

### Docker Compose (with Redis)

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
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    restart: unless-stopped

volumes:
  redis_data:
```

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

**Important:** When running multiple instances, use Redis for shared state:

```bash
export REDIS_URL=redis://localhost:6379
```

---

## Configuration Reference

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `FCAPTCHA_SECRET` | Yes | - | Secret key for signing tokens (min 16 chars) |
| `PORT` | No | 3000 | Server port |
| `REDIS_URL` | No | - | Redis URL for distributed state |
| `NODE_ENV` | No | development | Set to `production` for Node.js |

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
