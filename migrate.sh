#!/bin/bash
# migrate.sh — Ejecuta migraciones pendientes de la base de datos
# Uso: ./migrate.sh [docker_compose_file]
set -euo pipefail

COMPOSE_FILE="${1:-docker-compose.yml}"
MIGRATIONS_DIR="postgres/migrations"
STATE_TABLE="_schema_migrations"

# Cargar variables de .env (ignorando comentarios y líneas vacías)
if [ -f .env ]; then
  while IFS='=' read -r key value; do
    key=$(echo "$key" | xargs)
    [[ -z "$key" || "$key" =~ ^# ]] && continue
    value=$(echo "$value" | sed 's/^#.*//' | xargs)
    export "$key=$value"
  done < .env
fi

POSTGRES_USER="${POSTGRES_USER:-portal_user}"
POSTGRES_DB="${POSTGRES_DB:-portal_cautivo}"

echo "[MIGRATE] Verificando migraciones pendientes..."

# Crear tabla de estado de migraciones si no existe
docker compose -f "$COMPOSE_FILE" exec -T postgres psql \
  -U "$POSTGRES_USER" -d "$POSTGRES_DB" -q \
  -c "CREATE TABLE IF NOT EXISTS $STATE_TABLE (
    id          SERIAL PRIMARY KEY,
    filename    VARCHAR(255) UNIQUE NOT NULL,
    applied_at  TIMESTAMPTZ DEFAULT NOW()
  );" 2>/dev/null

# Obtener migraciones ya aplicadas
APPLIED=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql \
  -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At \
  -c "SELECT filename FROM $STATE_TABLE ORDER BY id;" 2>/dev/null)

PENDING=0
for migration in "$MIGRATIONS_DIR"/*.sql; do
  [ -f "$migration" ] || continue
  filename=$(basename "$migration")
  
  if echo "$APPLIED" | grep -q "^${filename}$"; then
    continue
  fi
  
  echo "[MIGRATE] Aplicando: $filename"
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql \
    -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    -f "/dev/stdin" < "$migration" 2>&1
  
  docker compose -f "$COMPOSE_FILE" exec -T postgres psql \
    -U "$POSTGRES_USER" -d "$POSTGRES_DB" -q \
    -c "INSERT INTO $STATE_TABLE (filename) VALUES ('$filename');" 2>/dev/null
  
  echo "[MIGRATE] ✓ $filename aplicada"
  PENDING=$((PENDING + 1))
done

if [ "$PENDING" -eq 0 ]; then
  echo "[MIGRATE] No hay migraciones pendientes."
else
  echo "[MIGRATE] $PENDING migración(es) aplicada(s)."
fi
