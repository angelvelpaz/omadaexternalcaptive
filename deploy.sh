#!/bin/bash
# deploy.sh — Script de deploy para el Portal Cautivo
# Uso: ./deploy.sh [--fresh]
#   --fresh: Deploy completo (rebuild desde cero, resetea DB)
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[DEPLOY]${NC} $1"; }
warn() { echo -e "${YELLOW}[DEPLOY]${NC} $1"; }
err()  { echo -e "${RED}[DEPLOY]${NC} $1"; }

FRESH=false
if [[ "${1:-}" == "--fresh" ]]; then
  FRESH=true
fi

# ─── 1. Validar prerequisitos ──────────────────────────────────────────────────
log "Paso 1/7: Validando prerequisitos..."

for cmd in docker git; do
  if ! command -v "$cmd" &>/dev/null; then
    err "$cmd no está instalado. Instálalo primero."
    exit 1
  fi
done

# Verificar Docker Compose v2
if ! docker compose version &>/dev/null; then
  err "Docker Compose v2+ no está disponible."
  exit 1
fi

# Verificar puertos
for port in 80 443; do
  if ss -tlnp 2>/dev/null | grep -q ":${port} " || netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
    warn "Puerto $port está en uso. Puede haber conflicto con nginx."
  fi
done

log "Prerequisitos OK."

# ─── 2. Generar .env si no existe ─────────────────────────────────────────────
log "Paso 2/7: Configurando variables de entorno..."

if [ ! -f .env ]; then
  if [ -f .env.example ]; then
    cp .env.example .env
    log "Archivo .env creado desde .env.example"
  else
    err "No existe .env ni .env.example. Crea un archivo .env primero."
    exit 1
  fi
fi

# Generar secrets si tienen valores por defecto
generate_secret() {
  openssl rand -hex 32 2>/dev/null || head -c 64 /dev/urandom | base64 | tr -d '/+=' | head -c 64
}

# Verificar y generar SESSION_SECRET
if grep -q "SESSION_SECRET=session_secret_muy_seguro_cambia_esto" .env; then
  NEW_SECRET=$(generate_secret)
  sed -i "s|SESSION_SECRET=session_secret_muy_seguro_cambia_esto|SESSION_SECRET=$NEW_SECRET|" .env
  log "SESSION_SECRET generado automáticamente."
fi

# Verificar y generar ADMIN_SECRET
if grep -q "ADMIN_SECRET=admin_secret_cambia_esto_en_produccion" .env; then
  NEW_SECRET=$(generate_secret)
  sed -i "s|ADMIN_SECRET=admin_secret_cambia_esto_en_produccion|ADMIN_SECRET=$NEW_SECRET|" .env
  log "ADMIN_SECRET generado automáticamente."
fi

# Verificar y generar WINBIND_MANAGER_TOKEN
if grep -q "WINBIND_MANAGER_TOKEN=$" .env && grep -q "WINBIND_MANAGER_TOKEN=$\s*$\|WINBIND_MANAGER_TOKEN=$" .env | grep -v "[a-f0-9]" &>/dev/null; then
  NEW_TOKEN=$(generate_secret)
  sed -i "s|WINBIND_MANAGER_TOKEN=.*|WINBIND_MANAGER_TOKEN=$NEW_TOKEN|" .env
  log "WINBIND_MANAGER_TOKEN generado automáticamente."
fi

# Verificar campos obligatorios
for var in POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD RADIUS_SECRET SESSION_SECRET ADMIN_SECRET; do
  value=$(grep "^${var}=" .env | cut -d'=' -f2-)
  if [ -z "$value" ] || echo "$value" | grep -q "cambia_esto\|seguro_cambia"; then
    err "Variable $var no está configurada o tiene valor por defecto. Edita .env."
    exit 1
  fi
done

log "Variables de entorno OK."

# ─── 3. Verificar certificados SSL ─────────────────────────────────────────────
log "Paso 3/7: Verificando certificados SSL..."

if [ ! -f ssl/portal.crt ] || [ ! -f ssl/portal.key ]; then
  warn "Certificados SSL no encontrados en ssl/portal.crt y ssl/portal.key"
  warn "Generando certificado autofirmado para desarrollo..."
  mkdir -p ssl
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout ssl/portal.key -out ssl/portal.crt \
    -subj "/CN=portal-cautivo/O=Dev/C=EC" 2>/dev/null
  log "Certificado autofirmado generado (válido 365 días)."
fi

# Verificar certificados WPA Enterprise
if [ ! -f freecerts/ca.pem ] || [ ! -f freecerts/server.crt ] || [ ! -f freecerts/server.key ]; then
  warn "Certificados WPA Enterprise no encontrados en freecerts/"
  warn "Los clientes WPA Enterprise no funcionarán sin estos certificados."
  warn "Generando certificados temporales..."
  mkdir -p freecerts
  cd freeradius && make cert 2>/dev/null && cd ..
  if [ -f freeradius/ca.pem ]; then
    cp freeradius/ca.pem freecerts/ca.pem
    cp freeradius/server.crt freecerts/server.crt
    cp freeradius/server.key freecerts/server.key
    log "Certificados WPA Enterprise temporales generados."
  else
    warn "No se pudieron generar certificados WPA Enterprise."
  fi
fi

log "Certificados SSL OK."

# ─── 4. Build de contenedores ──────────────────────────────────────────────────
log "Paso 4/7: Construyendo contenedores..."

if [ "$FRESH" = true ]; then
  docker compose build --no-cache
else
  docker compose build
fi

log "Contenedores construidos."

# ─── 5. Iniciar servicios ─────────────────────────────────────────────────────
log "Paso 5/7: Iniciando servicios..."

if [ "$FRESH" = true ]; then
  docker compose down -v
  docker compose up -d --build
else
  docker compose up -d
fi

log "Servicios iniciados."

# ─── 6. Esperar a que los servicios estén sanos ────────────────────────────────
log "Paso 6/7: Esperando a que los servicios estén listos..."

MAX_WAIT=120
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
  HEALTHY=$(docker compose ps --format json 2>/dev/null | grep -c '"healthy"' || echo 0)
  RUNNING=$(docker compose ps --format json 2>/dev/null | grep -c '"running"' || echo 0)
  
  if [ "$HEALTHY" -ge 1 ] && [ "$RUNNING" -ge 3 ]; then
    log "Servicios listos ($HEALTHY healthy, $RUNNING running)."
    break
  fi
  
  sleep 5
  WAITED=$((WAITED + 5))
  echo -ne "\r[DEPLOY] Esperando... ($WAITED/${MAX_WAIT}s)"
done

if [ $WAITED -ge $MAX_WAIT ]; then
  warn "Timeout esperando servicios. Verifica con: docker compose ps"
fi

# ─── 7. Ejecutar migraciones y verificar ───────────────────────────────────────
log "Paso 7/7: Ejecutando migraciones de base de datos..."

if [ -d postgres/migrations ]; then
  bash migrate.sh
else
  warn "Directorio postgres/migrations no encontrado. Saltando migraciones."
fi

# Verificación final
log "Verificación final..."
echo ""

# Status de contenedores
echo "=== Estado de servicios ==="
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"

echo ""

# Health check del portal
HTTP_CODE=$(curl -sk -o /dev/null -w '%{http_code}' https://localhost/health 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
  log "Portal: ✅ Health check OK"
else
  warn "Portal: ⚠️ Health check retornó HTTP $HTTP_CODE"
fi

# Test de login admin
LOGIN_RESP=$(curl -sk -X POST https://localhost/admin/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"'"$(grep ADMIN_SECRET .env | cut -d= -f2-)"'"}' 2>/dev/null)
if echo "$LOGIN_RESP" | grep -q '"success":true'; then
  log "Admin login: ✅ Funcional"
else
  warn "Admin login: ⚠️ Verificar credenciales"
fi

echo ""
log "═══════════════════════════════════════════════════════════"
log "Deploy completado exitosamente."
log ""
log "Acceso al panel admin: https://$(hostname -I | awk '{print $1}'):443/admin"
log "Usuario: admin"
log "Contraseña: $(grep ADMIN_SECRET .env | cut -d= -f2-)"
log ""
log "Para ver logs: docker compose logs -f"
log "Para detener: docker compose down"
log "Para backups: ./backup.sh"
log "═══════════════════════════════════════════════════════════"
