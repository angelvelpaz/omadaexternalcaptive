#!/bin/bash
set -e

# Sustituir variables de entorno en los archivos de configuración.
# Los archivos .template son plantillas; se generan los archivos finales.
# Esto evita hardcodear secretos en la imagen Docker.

RADDB=/etc/raddb

if [ -z "$RADIUS_SECRET" ] || [ -z "$POSTGRES_HOST" ] || [ -z "$POSTGRES_DB" ] || [ -z "$POSTGRES_USER" ] || [ -z "$POSTGRES_PASSWORD" ]; then
  echo "[FREERADIUS] RADIUS_SECRET y las credenciales de PostgreSQL son obligatorios."
  exit 1
fi

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

# Instalar certificados WPA-Enterprise externos y generar el PEM que usa EAP.
CERT_SOURCE="$RADDB/custom-certs"
if [ -f "$CERT_SOURCE/ca.pem" ] && [ -f "$CERT_SOURCE/server.crt" ] && [ -f "$CERT_SOURCE/server.key" ]; then
  echo "[FREERADIUS] Instalando certificados WPA-Enterprise desde $CERT_SOURCE..."
  cp "$CERT_SOURCE/ca.pem" "$RADDB/certs/ca.pem"
  cp "$CERT_SOURCE/server.crt" "$RADDB/certs/server.crt"
  cp "$CERT_SOURCE/server.key" "$RADDB/certs/server.key"
  # El cliente Android necesita recibir el certificado del servidor seguido
  # por toda la cadena intermedia antes de la clave privada.
  cat "$CERT_SOURCE/server.crt" "$CERT_SOURCE/ca.pem" "$CERT_SOURCE/server.key" > "$RADDB/certs/server.pem"
  chown freerad:freerad "$RADDB/certs/ca.pem" "$RADDB/certs/server.crt" "$RADDB/certs/server.key" "$RADDB/certs/server.pem"
  chmod 640 "$RADDB/certs/ca.pem" "$RADDB/certs/server.crt" "$RADDB/certs/server.key" "$RADDB/certs/server.pem"
else
  echo "[FREERADIUS] Advertencia: no se encontraron certificados completos en $CERT_SOURCE."
  echo "[FREERADIUS] Generando certificados autofirmados temporales para que FreeRADIUS pueda iniciar..."
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "$RADDB/certs/server.key" \
    -out "$RADDB/certs/server.crt" \
    -subj "/CN=portal-cautivo/O=PortalCautivo/C=EC" 2>/dev/null
  # Generar CA autofirmada (el server.crt ES la CA en este caso)
  cp "$RADDB/certs/server.crt" "$RADDB/certs/ca.pem"
  # Generar server.pem (Android)
  cat "$RADDB/certs/server.crt" "$RADDB/certs/server.key" > "$RADDB/certs/server.pem"
  chown freerad:freerad "$RADDB/certs/ca.pem" "$RADDB/certs/server.crt" "$RADDB/certs/server.key" "$RADDB/certs/server.pem"
  chmod 640 "$RADDB/certs/ca.pem" "$RADDB/certs/server.crt" "$RADDB/certs/server.key" "$RADDB/certs/server.pem"
  echo "[FREERADIUS] Certificados autofirmados generados. Suba los certificados reales desde el panel admin."
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

	options {
		chase_referrals = yes
		rebind = yes
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

# El agente se limita a la red Docker (no hay puerto publicado en Compose).
# Si Winbind no se configura, FreeRADIUS mantiene su arranque normal.
if [ "${WINBIND_MANAGER_ENABLED:-false}" = "true" ] && [ -n "${WINBIND_MANAGER_TOKEN:-}" ]; then
  # Asegurar que el DC sea resoluble via /etc/hosts para Kerberos/Samba
  LDAP_DC=$(echo "$LDAP_URL" | sed 's|ldap[s]*://||' | sed 's|:.*||')
  if [ -n "$LDAP_DC" ] && [ "$LDAP_DC" != "localhost" ]; then
    LDAP_REALM=$(echo "$LDAP_GROUP" | grep -oP 'DC=\K[^,]+' | head -1 | tr '[:lower:]' '[:upper:]')
    LDAP_REALM="${LDAP_REALM:-GPP}"
    if ! grep -q "$LDAP_DC" /etc/hosts 2>/dev/null; then
      echo "$LDAP_DC ${LDAP_REALM,,}.net ${LDAP_REALM,,}.net" >> /etc/hosts
      echo "[FREERADIUS] Agregado $LDAP_DC a /etc/hosts para DNS resolution"
    fi
  fi

  if getent group sambashare >/dev/null 2>&1; then
    usermod -a -G sambashare freerad || true
  fi
  mkdir -p /var/lib/samba/winbindd_privileged
  chgrp sambashare /var/lib/samba/winbindd_privileged 2>/dev/null || true
  chmod 750 /var/lib/samba/winbindd_privileged 2>/dev/null || true
  echo "[FREERADIUS] Iniciando agente interno Winbind en ${WINBIND_AGENT_PORT:-8765}..."
  python3 /usr/local/bin/winbind_manager.py >/var/log/winbind-manager.log 2>&1 &
else
  echo "[FREERADIUS] Agente Winbind desactivado; se conserva el flujo LDAP/WPA existente."
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
