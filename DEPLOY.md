# CrashSwitch License Server — Deployment Guide

## Deploy to Railway (free, always-on)

### Step 1 — Create accounts
- GitHub: https://github.com (free)
- Railway: https://railway.app (free tier, no credit card)

### Step 2 — Push server code to GitHub
1. Create a new **private** repository on GitHub called `crashswitch-server`
2. Upload the contents of this `CrashSwitchServer` folder to it
3. Make sure `.gitignore` is included (it excludes `private.pem` and `.env`)

### Step 3 — Deploy on Railway
1. Go to https://railway.app → New Project → Deploy from GitHub repo
2. Select your `crashswitch-server` repo
3. Railway auto-detects Node.js and deploys it
4. Click **Add Plugin** → **PostgreSQL** — Railway provisions a free DB automatically

### Step 4 — Generate your RSA keypair
On your local machine (needs Node.js installed):
```
cd CrashSwitchServer
npm install
node scripts/generateKeys.js
```
This creates:
- `private.pem` — **never share this, never commit it**
- `public.pem` — copy this into your CrashSwitch project folder before building

### Step 5 — Generate admin password hash
```
node -e "require('bcrypt').hash('YOUR_PASSWORD_HERE', 12).then(console.log)"
```
Copy the output — you'll need it in Step 6.

### Step 6 — Set environment variables in Railway
In Railway → your project → Variables, add:

| Variable | Value |
|---|---|
| `DATABASE_URL` | Auto-filled by Railway when you add PostgreSQL |
| `PRIVATE_KEY` | Full contents of `private.pem` (paste with literal `\n` for newlines) |
| `ADMIN_PASSWORD_HASH` | The bcrypt hash from Step 5 |

### Step 7 — Set up the database
Get your DATABASE_URL from Railway, then run locally:
```
DATABASE_URL="your_railway_db_url" node scripts/setupDb.js
```

### Step 8 — Get your server URL
Railway gives you a URL like `https://crashswitch-server-production.up.railway.app`
Update `ServerUrl` in `CrashSwitch/src/AuthService.cs` to match.

---

## Managing keys

All admin endpoints require your password as a Bearer token:
```
Authorization: Bearer YOUR_PASSWORD_HERE
```

### Create a key (365 days)
```
POST /admin/keys
{ "note": "customer name", "days": 365 }
```

### Create a key (30 days trial)
```
POST /admin/keys
{ "note": "trial user", "days": 30 }
```

### List all keys
```
GET /admin/keys
```

### Revoke a key instantly
```
DELETE /admin/keys/CRASH-XXXX-XXXX-XXXX-XXXX
```

### Reset HWID (user got a new PC)
```
POST /admin/keys/CRASH-XXXX-XXXX-XXXX-XXXX/reset-hwid
```

### View recent auth attempts
```
GET /admin/logs
```

You can use any HTTP client — curl, Postman, Insomnia, or a browser extension.

---

## Key format
Keys are generated in the format: `CRASH-XXXX-XXXX-XXXX-XXXX`
Example: `CRASH-A1B2-C3D4-E5F6-G7H8`

---

## Security model summary

1. Client sends `{ key, hwid }` to `/auth/verify`
2. Server checks key exists, not expired, not revoked, HWID matches (or binds on first use)
3. Server signs a JWT with RS256 **private key** (never leaves server)
4. Client verifies JWT signature using **public key** (embedded in exe)
5. Client also validates issuer, audience, expiry, and HWID in token
6. Token lasts 30 minutes — client silently re-validates every 25 minutes
7. If server is unreachable during re-validation, app keeps running until token expires
8. If key is revoked, next re-validation fails and app notifies user

The private key **never leaves Railway**. The exe only contains the public key,
which can only verify signatures — it cannot forge them.
