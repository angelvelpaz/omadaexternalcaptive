FROM freeradius/freeradius-server:latest-3.2

# Instalar envsubst (gettext), módulo LDAP y cliente postgresql para FreeRADIUS
USER root
RUN apt-get update && apt-get install -y --no-install-recommends gettext-base freeradius-ldap postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copiar configuración con plantillas
COPY config/ /etc/raddb/

# Habilitar módulos SQL y LDAP (crear symlinks)
RUN ln -sf /etc/raddb/mods-available/sql /etc/raddb/mods-enabled/sql \
    && ln -sf /etc/raddb/mods-available/ldap /etc/raddb/mods-enabled/ldap \
    && chown -R freerad:freerad /etc/raddb

# Script de entrada que sustituye variables y arranca freeradius
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 1812/udp 1813/udp

ENTRYPOINT ["/entrypoint.sh"]
