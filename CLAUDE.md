# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Iniciar todo el stack
docker compose up -d --build

# Ver logs en tiempo real
docker compose logs -f portal
docker compose logs -f freeradius

# Reiniciar un servicio específico
docker compose restart portal

# Acceder a PostgreSQL
docker compose exec postgres psql -U $POSTGRES_USER -d $POSTGRES_DB

# Probar RADIUS manualmente (requiere freeradius-utils instalado en el host)
radtest <cedula> <radius_password> localhost 1812 <RADIUS_SECRET>

# Ejecutar un test unitario de validación de cédula
node -e "const c = require('./portal/src/services/cedula'); console.log(c.validate('1713175071'))"
```

## Architecture

Four Docker containers on a private bridge network (`captive_net`):

```
[nginx :80/:443] → [portal :3000] → [freeradius :1812/udp]
                               ↘  → [postgres :5432]
```

**Startup order**: `postgres` (with healthcheck) → `freeradius` + `portal` (both wait for postgres healthy) → `nginx`.

### Portal (`portal/`)

Node.js/Express app. Key integration points:

- **Vendor detection** (`src/routes/index.js`): Detects MikroTik/UniFi/Omada from query params. MikroTik has `link-login`, UniFi has `cmd`+`id`, Omada has `clientMac`+`vid`.
- **RADIUS auth** (`src/services/radius.js`): Opens a UDP socket per request via `radius` npm package. Shared secret in `.env` must exactly match `freeradius/config/clients.conf.template`. Silent failure if they mismatch.
- **MikroTik redirect**: After auth, returns a `__mikrotik__:{url}:{user}:{pass}` string — the frontend builds a hidden form and auto-submits it via POST to MikroTik's login CGI. This is the required protocol; a plain HTTP redirect won't work.
- **UniFi** (`src/services/unifi.js`): Server-side API call to the UniFi controller with session cookie auth.
- **Omada** (`src/services/omada.js`): Server-side OAuth2 client credentials + extPortal API call.

### FreeRADIUS (`freeradius/`)

- Config files use `${VAR}` syntax — `entrypoint.sh` runs `envsubst` on `*.template` files before starting.
- `mods-available/sql.template` → generates `mods-available/sql` at runtime with DB credentials.
- `clients.conf.template` → generates `clients.conf` at runtime with the RADIUS shared secret.
- Authenticates via PAP: looks up `radcheck.value` (Cleartext-Password) for the username.
- `sites-enabled/default`: authorize section calls `sql` then `pap`; authenticate section uses `Auth-Type PAP`.

### PostgreSQL (`postgres/`)

Init scripts run in order on first startup:
- `01-schema.sql`: creates `usuarios_portal`, all FreeRADIUS rlm_sql tables (`radcheck`, `radreply`, `radgroupcheck`, `radgroupreply`, `radusergroup`, `radacct`), and `access_log`.
- `02-seed.sql`: inserts one test user (cédula `1713175071`) with matching `radcheck` entry.

**Critical constraint**: `radcheck` column names (`username`, `attribute`, `op`, `value`) must match exactly what's referenced in `mods-available/sql.template`. Any mismatch causes all RADIUS auths to silently fail.

When registering a user, `database.js:createUser()` runs a transaction that inserts into both `usuarios_portal` and `radcheck` simultaneously.

### Nginx (`nginx/`)

- Self-signed TLS cert generated at Docker build time via `openssl` in the Dockerfile.
- Port 80 serves captive portal detection endpoints (`/generate_204`, `/hotspot-detect.html`, `/ncsi.txt`) and redirects everything else to HTTPS.
- Port 443 proxies to `portal:3000`.

## Key env vars

| Var | Used by |
|-----|---------|
| `RADIUS_SECRET` | `freeradius/config/clients.conf.template` AND `portal/src/services/radius.js` — must match |
| `POSTGRES_*` | Both `portal` and `freeradius` containers |
| `PORTAL_NAME` | Exposed via `GET /auth/config`, read by all HTML pages |
| `SESSION_DURATION_MINUTES` | Passed to UniFi/Omada API calls and displayed in success page |
