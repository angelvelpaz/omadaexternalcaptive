#!/bin/bash
set -e

# Sustituir variables de entorno en los archivos de configuración.
# Los archivos .template son plantillas; se generan los archivos finales.
# Esto evita hardcodear secretos en la imagen Docker.

RADDB=/etc/raddb

echo "[FREERADIUS] Procesando configuración con variables de entorno..."

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

# Esperar a que la base de datos PostgreSQL esté en línea
echo "[FREERADIUS] Esperando a la base de datos en $POSTGRES_HOST:5432..."
until PGPASSWORD=$POSTGRES_PASSWORD psql -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c '\q' >/dev/null 2>&1; do
  sleep 1
done
echo "[FREERADIUS] Base de datos conectada. Extrayendo parámetros de Active Directory (LDAP)..."

# Extraer parámetros de configuración de LDAP desde la tabla de base de datos
LDAP_URL=$(PGPASSWORD=$POSTGRES_PASSWORD psql -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -A -c "SELECT config->>'ldapServerUrl' FROM controller_config WHERE vendor='ldap' LIMIT 1" 2>/dev/null || true)
LDAP_BIND_DN=$(PGPASSWORD=$POSTGRES_PASSWORD psql -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -A -c "SELECT config->>'ldapBindDN' FROM controller_config WHERE vendor='ldap' LIMIT 1" 2>/dev/null || true)
LDAP_PASS=$(PGPASSWORD=$POSTGRES_PASSWORD psql -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -A -c "SELECT config->>'ldapBindCredentials' FROM controller_config WHERE vendor='ldap' LIMIT 1" 2>/dev/null || true)
LDAP_BASE=$(PGPASSWORD=$POSTGRES_PASSWORD psql -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -A -c "SELECT config->>'ldapSearchBase' FROM controller_config WHERE vendor='ldap' LIMIT 1" 2>/dev/null || true)
LDAP_GROUP=$(PGPASSWORD=$POSTGRES_PASSWORD psql -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -A -c "SELECT config->>'ldapAllowedGroup' FROM controller_config WHERE vendor='ldap' LIMIT 1" 2>/dev/null || true)

# Usar valores de fallback por defecto en caso de que aún no existan registros en la base de datos
LDAP_URL="${LDAP_URL:-localhost}"
LDAP_BIND_DN="${LDAP_BIND_DN:-cn=admin,dc=example,dc=org}"
LDAP_PASS="${LDAP_PASS:-password}"
LDAP_BASE="${LDAP_BASE:-dc=example,dc=org}"
LDAP_GROUP="${LDAP_GROUP:-}"

echo "[FREERADIUS] Generando archivo mods-available/ldap..."
cat <<EOF > "$RADDB/mods-available/ldap"
# Generado dinámicamente al iniciar desde la base de datos PostgreSQL
ldap {
	server = '${LDAP_URL}'
	port = 389
	identity = '${LDAP_BIND_DN}'
	password = '${LDAP_PASS}'
	base_dn = '${LDAP_BASE}'

	sasl {
	}

	tls {
		start_tls = no
		require_cert = never
	}

	user {
		base_dn = "\${..base_dn}"
		filter = "(|(sAMAccountName=%{%{Stripped-User-Name}:-%{User-Name}})(userPrincipalName=%{%{Stripped-User-Name}:-%{User-Name}}))"
		scope = 'sub'
	}

	group {
		base_dn = "\${..base_dn}"
		filter = '(objectClass=group)'
		scope = 'sub'
		name_attribute = cn
		membership_filter = "(|(&(objectClass=group)(member=%{control:Ldap-UserDn}))(&(objectClass=user)(sAMAccountName=%{%{Stripped-User-Name}:-%{User-Name}})))"
		name = '${LDAP_GROUP}'
	}

	update {
		control:Password-With-Header	+= 'userPassword'
	}

	# start=0 y min=0 para permitir que FreeRADIUS inicie incluso si el servidor LDAP está offline
	pool {
		start = 0
		min = 0
		max = 30
		spare = 3
		uses = 0
		lifetime = 0
		idle_timeout = 60
	}
}
EOF

# Habilitar copia de atributos del túnel interno al túnel externo (use_tunneled_reply = yes)
if [ -f "$RADDB/mods-available/eap" ]; then
  sed -i 's/use_tunneled_reply = no/use_tunneled_reply = yes/g' "$RADDB/mods-available/eap"
  sed -i 's/default_eap_type = md5/default_eap_type = peap/g' "$RADDB/mods-available/eap"
  echo "[FREERADIUS] Modificado: use_tunneled_reply = yes y default_eap_type = peap en mods-available/eap"
fi

# Hilo en segundo plano para recarga en caliente al detectar cambios en .reload
(
  LAST_RELOAD=""
  while true; do
    if [ -f "$RADDB/certs/.reload" ]; then
      CURRENT_RELOAD=$(cat "$RADDB/certs/.reload" 2>/dev/null || true)
      if [ "$CURRENT_RELOAD" != "$LAST_RELOAD" ]; then
        LAST_RELOAD="$CURRENT_RELOAD"
        echo "[FREERADIUS] Detectado cambio en certificados (.reload). Recargando configuración..."
        # Esperar 1 segundo para asegurar la escritura completa de los archivos
        sleep 1
        # Ajustar permisos antes de enviar señal
        chown -R freerad:freerad "$RADDB/certs"
        pkill -HUP freeradius || true
      fi
    fi
    sleep 5
  done
) &

# Ajustar permisos
chown -R freerad:freerad "$RADDB"

echo "[FREERADIUS] Iniciando freeradius..."
exec freeradius -f -l stdout "$@"
