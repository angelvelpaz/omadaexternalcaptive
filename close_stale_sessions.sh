#!/bin/bash
# close_stale_sessions.sh — Cierra sesiones RADIUS stale (abiertas hace más de X horas)
# Uso: ./close_stale_sessions.sh [horas] [docker_compose_file]
set -euo pipefail

HOURS="${1:-8}"
COMPOSE_FILE="${2:-docker-compose.yml}"

# Cargar variables de .env
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

echo "[CLEANUP] Cerrando sesiones stale (abiertas hace más de ${HOURS}h)..."

RESULT=$(docker compose -f "$COMPOSE_FILE" exec -T postgres psql \
  -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At \
  -c "UPDATE radacct SET acctstoptime = NOW(), acctsessiontime = GREATEST(0, EXTRACT(EPOCH FROM (NOW() - acctstarttime))::bigint) WHERE acctstoptime IS NULL AND acctstarttime < NOW() - INTERVAL '${HOURS} hours';" 2>&1)

AFFECTED=$(echo "$RESULT" | grep -oP '\d+ (?=fila)' || echo "0")
echo "[CLEANUP] Sesiones cerradas: ${AFFECTED:-0}"

echo "[CLEANUP] Estado actual de sesiones activas:"
docker compose -f "$COMPOSE_FILE" exec -T postgres psql \
  -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c \
  "SELECT COUNT(*) AS activas FROM radacct WHERE acctstoptime IS NULL;" 2>&1
