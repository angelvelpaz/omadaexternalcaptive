# Portal Cautivo Externo

Sistema de portal cautivo dockerizado compatible con **MikroTik**, **Ubiquiti UniFi** y **TP-Link Omada**.

Autentica usuarios mediante número de cédula ecuatoriana y autoriza el acceso a internet vía FreeRADIUS + PostgreSQL.

---

## Requisitos

- Docker Engine 24+
- Docker Compose v2+
- Puertos libres en el host: `80`, `443`, `1812/udp`, `1813/udp`

---

## Instalación

```bash
git clone <repo> captiveportal
cd captiveportal

# 1. Copiar y editar variables de entorno
cp .env.example .env
nano .env

# 2. Construir e iniciar
docker compose up -d --build

# 3. Verificar que todos los contenedores estén corriendo
docker compose ps
```

El portal queda disponible en:
- `https://<IP_DEL_HOST>` (vía nginx con certificado autofirmado)
- `http://<IP_DEL_HOST>:3000` (directo al portal, sin TLS)

---

## Variables de entorno críticas

| Variable | Descripción |
|---|---|
| `POSTGRES_PASSWORD` | Contraseña de la base de datos |
| `RADIUS_SECRET` | Shared secret RADIUS (debe coincidir con el equipo de red) |
| `SESSION_SECRET` | Secreto para sesiones Express |
| `PORTAL_NAME` | Nombre que aparece en la UI del portal |

---

## Configuración por vendor

### MikroTik Hotspot

En el router MikroTik, configure el hotspot con login page externa:

```
/ip hotspot profile set [find] login-by=http-chap http-login-page=https://<IP_PORTAL>/
```

O desde Winbox:
1. IP → Hotspot → Profiles → pestaña "Login"
2. **Login By**: HTTP CHAP
3. **HTTP Login Page**: `https://<IP_PORTAL>/`

El equipo redirigirá a la URL configurada con estos parámetros:
```
https://<IP_PORTAL>/?mac=XX:XX:XX&ip=192.168.x.x&username=&link-login=http://...&link-orig=http://...
```

**FreeRADIUS en MikroTik:**
```
/radius add service=hotspot address=<IP_PORTAL> secret=<RADIUS_SECRET> authentication-port=1812 accounting-port=1813
/ip hotspot profile set [find] use-radius=yes
```

---

### Ubiquiti UniFi

1. En el **UniFi Network Controller**, vaya a Settings → Profiles → Guest Control
2. Habilite **Guest Portal**
3. Seleccione **External Portal Server**
4. Configure **Custom Portal URL**: `https://<IP_PORTAL>/`

Variables requeridas en `.env`:
```env
UNIFI_CONTROLLER_URL=https://<IP_CONTROLADOR>:8443
UNIFI_USER=admin
UNIFI_PASS=<contraseña>
UNIFI_SITE=default
UNIFI_VERIFY_SSL=false
```

El portal recibirá:
```
https://<IP_PORTAL>/?id=<CLIENT_MAC>&ap=<AP_MAC>&ssid=<SSID>&t=<TIMESTAMP>&url=<URL_ORIGINAL>&cmd=login
```

---

### TP-Link Omada

1. En el **Omada Controller**, vaya a Settings → Authentication → Portal
2. Tipo: **External Webpage**
3. URL del portal: `https://<IP_PORTAL>/`

Crear credenciales de API en Omada:
1. Settings → Access Control → Access Tokens
2. Crear cliente con permisos de **Hotspot Manager**

Variables requeridas en `.env`:
```env
OMADA_CONTROLLER_URL=https://<IP_CONTROLADOR>:8043
OMADA_SITE_ID=<site_id>
OMADA_CLIENT_ID=<client_id>
OMADA_CLIENT_SECRET=<client_secret>
```

El portal recibirá:
```
https://<IP_PORTAL>/?clientMac=XX:XX:XX&apMac=XX:XX:XX&ssidName=<SSID>&radioId=0&vid=1&redirectUrl=<URL>
```

---

## Verificación y pruebas

### Estado de los contenedores
```bash
docker compose ps
docker compose logs -f portal
docker compose logs -f freeradius
```

### Probar autenticación RADIUS manualmente
```bash
# Instalar radtest (cliente de prueba)
apt-get install freeradius-utils

# Probar con usuario de seed (cédula: 1713175071)
radtest 1713175071 a1b2c3d4-e5f6-7890-abcd-ef1234567890 localhost 1812 <RADIUS_SECRET>

# Respuesta esperada: Access-Accept
```

### Probar el API del portal
```bash
# Verificar que el portal responde
curl -k https://localhost/auth/config

# Verificar cédula
curl -k -X POST https://localhost/auth/check \
  -H 'Content-Type: application/json' \
  -d '{"cedula":"1713175071"}'
# Respuesta: {"valid":true,"exists":true}

# Verificar cédula inválida
curl -k -X POST https://localhost/auth/check \
  -H 'Content-Type: application/json' \
  -d '{"cedula":"1234567890"}'
# Respuesta: {"valid":false,"exists":false,"error":"Número de cédula no válido."}
```

### Probar registro completo
```bash
curl -k -X POST https://localhost/auth/register \
  -H 'Content-Type: application/json' \
  -d '{
    "cedula": "0102030405",
    "nombres": "Juan",
    "apellidos": "Perez",
    "email": "juan@test.com",
    "vendor": "unknown",
    "vendorParams": {}
  }'
```

### Consultar usuarios en base de datos
```bash
docker compose exec postgres psql -U $POSTGRES_USER -d $POSTGRES_DB -c \
  "SELECT cedula, nombres, apellidos, fecha_registro FROM usuarios_portal;"
```

---

## Troubleshooting

### FreeRADIUS no inicia
```bash
docker compose logs freeradius
```
Causas comunes:
- PostgreSQL no está listo aún → espere y ejecute `docker compose restart freeradius`
- `RADIUS_SECRET` vacío → verifique que `.env` tenga el valor configurado
- Tablas SQL no existen → verifique que el init de PostgreSQL corrió correctamente

### El portal no puede conectarse a PostgreSQL
```bash
docker compose exec portal node -e "require('./src/services/database').connect().then(() => console.log('OK')).catch(console.error)"
```

### RADIUS devuelve Access-Reject para un usuario existente
```bash
# Verificar que el usuario existe en radcheck
docker compose exec postgres psql -U $POSTGRES_USER -d $POSTGRES_DB -c \
  "SELECT * FROM radcheck WHERE username='<cedula>';"

# El password en radcheck debe coincidir con radius_password en usuarios_portal
docker compose exec postgres psql -U $POSTGRES_USER -d $POSTGRES_DB -c \
  "SELECT u.cedula, u.radius_password, r.value AS radcheck_password
   FROM usuarios_portal u
   JOIN radcheck r ON r.username = u.cedula
   WHERE u.cedula = '<cedula>';"
```

### Resetear todo (borrar datos)
```bash
docker compose down -v  # ADVERTENCIA: borra el volumen de PostgreSQL
docker compose up -d --build
```

### Certificado SSL no aceptado por el browser
El certificado es autofirmado. El browser mostrará una advertencia. En producción, reemplace los certificados en el contenedor nginx:
```bash
# Copiar certificados reales
docker compose exec nginx sh -c "cat > /etc/nginx/ssl/portal.crt" < /path/to/cert.pem
docker compose exec nginx sh -c "cat > /etc/nginx/ssl/portal.key" < /path/to/key.pem
docker compose exec nginx nginx -s reload
```

---

## Arquitectura

```
Internet / Equipo Wi-Fi
        │
   ┌────▼────┐
   │  Nginx  │  :80 (HTTP → HTTPS redirect + captive portal detection)
   │         │  :443 (TLS termination)
   └────┬────┘
        │
   ┌────▼────────────┐
   │  Portal Web     │  Node.js/Express :3000
   │  (Node.js)      │  - Validación cédula (módulo 10)
   │                 │  - Detección de vendor (MikroTik/UniFi/Omada)
   └─────┬──────┬────┘
         │      │
    ┌────▼──┐ ┌─▼──────────┐
    │ RADIUS│ │ PostgreSQL │
    │ :1812 │ │            │
    │  UDP  │ │ - usuarios │
    └───────┘ │ - radcheck │
              │ - radacct  │
              └────────────┘
```

### Flujo de autenticación

1. Cliente conecta al Wi-Fi → equipo redirige a `https://<IP_PORTAL>/?<vendor_params>`
2. Portal detecta el vendor por los parámetros GET
3. Usuario ingresa su cédula → `POST /auth/check` verifica si existe en DB
4. **Usuario nuevo**: formulario de registro → `POST /auth/register` → crea usuario + radcheck
5. **Usuario existente**: `POST /auth/login` → busca credenciales en DB
6. Portal envía `Access-Request` UDP a FreeRADIUS → FreeRADIUS consulta radcheck en PostgreSQL
7. Si `Access-Accept`:
   - **MikroTik**: frontend hace POST automático a `link-login` con username/password
   - **UniFi**: portal llama API del controlador (`POST /api/s/{site}/cmd/stamgr`)
   - **Omada**: portal obtiene token OAuth2 y llama API extPortal
8. Usuario accede a internet
