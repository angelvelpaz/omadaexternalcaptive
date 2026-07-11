#!/bin/bash
set -e

# Sustituir variables de entorno en los archivos de configuración.
# Los archivos .template son plantillas; se generan los archivos finales.
# Esto evita hardcodear secretos en la imagen Docker.

RADDB=/etc/raddb

echo "[FREERADIUS] Procesando configuración con variables de entorno..."

# Procesar cada archivo .template en raddb
# IMPORTANTE: especificar las variables exactas para que envsubst NO toque
# las referencias internas de FreeRADIUS del tipo ${thread[pool].x}

if [ -f "$RADDB/clients.conf.template" ]; then
  envsubst '${RADIUS_SECRET}' \
    < "$RADDB/clients.conf.template" \
    > "$RADDB/clients.conf"
  echo "[FREERADIUS] Generado: $RADDB/clients.conf"
fi

if [ -f "$RADDB/mods-available/sql.template" ]; then
  envsubst '${POSTGRES_HOST}${POSTGRES_PORT}${POSTGRES_USER}${POSTGRES_PASSWORD}${POSTGRES_DB}' \
    < "$RADDB/mods-available/sql.template" \
    > "$RADDB/mods-available/sql"
  echo "[FREERADIUS] Generado: $RADDB/mods-available/sql"
fi

# Ajustar permisos
chown -R freerad:freerad "$RADDB"

echo "[FREERADIUS] Iniciando freeradius..."
exec freeradius -f -l stdout "$@"
