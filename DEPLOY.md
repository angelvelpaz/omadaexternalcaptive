# Guía de Deploy — Portal Cautivo

Guía paso a paso para desplegar el Portal Cautivo en un nuevo servidor.

---

## Requisitos del Host

| Requisito | Mínimo |
|-----------|--------|
| Sistema operativo | Linux (Ubuntu 22.04+, Debian 12+, Alpine 3.18+) |
| Docker Engine | 24+ |
| Docker Compose | v2+ (`docker compose` sin guion) |
| RAM | 2 GB (4 GB recomendado) |
| Disco | 20 GB libres |
| Puertos libres | `80/tcp`, `443/tcp`, `1812/udp`, `1813/udp` |

### Instalar Docker (si no existe)

```bash
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker
```

---

## Deploy Rápido (automático)

```bash
# 1. Clonar el repositorio
git clone <repo> /opt/captiveportal
cd /opt/captiveportal

# 2. Ejecutar deploy (genera .env, secrets, certificados, migraciones)
chmod +x deploy.sh migrate.sh
./deploy.sh
```

El script `deploy.sh` ejecuta automáticamente:
1. Validación de prerequisitos
2. Generación de `.env` con secrets aleatorios
3. Certificados SSL autofirmados (si no existen)
4. Build de contenedores Docker
5. Inicio de servicios
6. Espera de health check (hasta 120s)
7. Migraciones de base de datos

### Opciones del deploy

```bash
./deploy.sh            # Deploy incremental (actualiza sin perder datos)
./deploy.sh --fresh    # Deploy completo (rebuild + reset DB)
```

---

## Deploy Manual (paso a paso)

### Paso 1: Clonar y configurar

```bash
git clone <repo> /opt/captiveportal
cd /opt/captiveportal

# Crear archivo .env
cp .env.example .env
nano .env  # Editar con valores de producción
```

### Paso 2: Variables de entorno obligatorias

```env
# Base de datos
POSTGRES_DB=portal_cautivo
POSTGRES_USER=portal_user
POSTGRES_PASSWORD=<contraseña-fuerte-aleatoria>

# RADIUS (debe coincidir con el equipo de red)
RADIUS_SECRET=<shared-secret-equipos-red>

# Seguridad
SESSION_SECRET=<aleatorio-64-char>
ADMIN_SECRET=<aleatorio-64-char>

# Zona horaria
TZ=America/Guayaquil
```

Generar secrets aleatorios:
```bash
openssl rand -hex 32
```

### Paso 3: Certificados SSL

```bash
# Crear directorios
mkdir -p ssl freecerts

# HTTPS para el portal (nginx)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ssl/portal.key -out ssl/portal.crt \
  -subj "/CN=tu-dominio.com"

# WPA Enterprise (FreeRADIUS)
# Opcional: generar certificados internos
cd freeradius && make cert && cd ..
cp freeradius/ca.pem freecerts/
cp freeradius/server.crt freecerts/
cp freeradius/server.key freecerts/
```

### Paso 4: Construir e iniciar

```bash
docker compose up -d --build
```

### Paso 5: Verificar servicios

```bash
# Estado de contenedores
docker compose ps

# Health check
curl -k https://localhost/health

# Login admin
curl -k -X POST https://localhost/admin/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<ADMIN_SECRET>"}'
```

### Paso 6: Migraciones de base de datos

```bash
chmod +x migrate.sh
./migrate.sh
```

Las migraciones son idempotentes y se trackean en la tabla `_schema_migrations`.

---

## Configuración por Vendor

### TP-Link Omada (recomendado)

```env
OMADA_CONTROLLER_URL=https://<IP_CONTROLADOR>:8043
OMADA_SITE_ID=<site_id>
OMADA_CLIENT_ID=<client_id>
OMADA_CLIENT_SECRET=<client_secret>
```

Portal: Settings → Authentication → Portal → External Webpage → `https://<IP_PORTAL>/`

### Ubiquiti UniFi

```env
UNIFI_CONTROLLER_URL=https://<IP_CONTROLADOR>:8443
UNIFI_USER=admin
UNIFI_PASS=<contraseña>
UNIFI_SITE=default
UNIFI_VERIFY_SSL=false
```

Portal: Settings → Profiles → Guest Control → External Portal Server → `https://<IP_PORTAL>/`

### MikroTik Hotspot

```bash
/radius add service=hotspot address=<IP_PORTAL> secret=<RADIUS_SECRET>
/ip hotspot profile set [find] use-radius=yes login-by=http-chap \
  http-login-page=https://<IP_PORTAL>/
```

### Winbind / Active Directory

```env
WINBIND_MANAGER_ENABLED=true
WINBIND_MANAGER_TOKEN=<token-aleatorio>
WINBIND_AGENT_PORT=8765
```

Desde el panel admin → Winbind / NTLM → Configurar dominio → Unir al dominio.

---

## Migraciones de Base de Datos

### Sistema de migraciones

Las migraciones están en `postgres/migrations/` y se ejecutan con `migrate.sh`:

```bash
./migrate.sh                    # Aplica migraciones pendientes
./migrate.sh docker-compose.yml # Usar archivo de compose personalizado
```

### Crear una nueva migración

```bash
# Crear archivo con número secuencial
cat > postgres/migrations/002_nombre_descriptivo.sql << 'EOF'
-- Descripción de la migración
ALTER TABLE ... ;
EOF

# Ejecutar
./migrate.sh
```

### Tabla de tracking

Las migraciones se registran en `_schema_migrations`:

```sql
SELECT filename, applied_at FROM _schema_migrations ORDER BY id;
```

---

## Backup y Restore

### Backup completo

```bash
./backup.sh
# Genera: backups/backup_captiveportal_YYYYMMDD_HHMMSS.tar.gz
```

El backup incluye:
- Dump de PostgreSQL
- Archivo `.env`
- Configuración nginx, FreeRADIUS, SSL
- Certificados WPA Enterprise

### Restore

```bash
# 1. Restaurar base de datos
tar xzf backups/backup_*.tar.gz
docker compose exec -T postgres psql -U $POSTGRES_USER -d $POSTGRES_DB < backup_*.sql

# 2. Restaurar configuración
cp backup_*/.env .env
cp -r backup_*/nginx/ nginx/
cp -r backup_*/freeradius/ freeradius/
cp -r backup_*/ssl/ ssl/

# 3. Reiniciar servicios
docker compose up -d
```

---

## Monitoreo

### Logs en tiempo real

```bash
docker compose logs -f portal        # Portal web
docker compose logs -f freeradius    # RADIUS + LDAP
docker compose logs -f postgres      # Base de datos
docker compose logs -f nginx         # Proxy inverso
```

### Health check

```bash
curl -k https://localhost/health
# {"status":"ok","postgresql":"ok","radius":"ok"}
```

### Estado de Winbind

```bash
docker compose exec freeradius wbinfo -t    # Verificar trust
docker compose exec freeradius net ads testjoin  # Verificar unión
docker compose exec freeradius ntlm_auth --username=<user> --password=<pass>
```

---

## Troubleshooting

| Problema | Solución |
|----------|----------|
| FreeRADIUS no inicia | `docker compose logs freeradius` — verificar PostgreSQL y tablas |
| Portal no conecta a DB | Verificar `POSTGRES_HOST=postgres` en `.env` |
| LDAP no responde | Verificar `LDAP_SERVER_URL` y conectividad al DC |
| Winbind trust roto | Re-unir: panel admin → Winbind → Unir al dominio |
| Certificado SSL no aceptado | Reemplazar `ssl/portal.crt` y `ssl/portal.key` con certificados reales |
| Puerto 80/443 ocupado | Verificar con `ss -tlnp \| grep :80` y detener el servicio conflictivo |
| VLAN no se asigna | Verificar `ldap_group_vlans` en DB y config LDAP en panel admin |

### Resetear completamente

```bash
docker compose down -v    # ⚠️ Borra volumen de PostgreSQL
docker compose up -d --build
./migrate.sh
```
