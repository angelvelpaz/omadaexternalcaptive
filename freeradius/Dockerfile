FROM freeradius/freeradius-server:latest-3.2

# Instalar envsubst (gettext), módulo LDAP, cliente PostgreSQL y dependencias
# necesarias para autenticación Winbind/NTLM contra Active Directory.
USER root
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    gettext-base freeradius-ldap postgresql-client python3 samba samba-common-bin \
    winbind libnss-winbind libpam-winbind krb5-user smbclient \
    && rm -rf /var/lib/apt/lists/*

# Copiar configuración con plantillas
COPY config/ /etc/raddb/

# Habilitar módulos SQL y LDAP (crear symlinks)
RUN ln -sf /etc/raddb/mods-available/sql /etc/raddb/mods-enabled/sql \
    && ln -sf /etc/raddb/mods-available/ldap /etc/raddb/mods-enabled/ldap \
    && ln -sf /etc/raddb/mods-available/mschap /etc/raddb/mods-enabled/mschap \
    && chown -R freerad:freerad /etc/raddb

# Script de entrada que sustituye variables y arranca freeradius
COPY entrypoint.sh /entrypoint.sh
COPY winbind_manager.py /usr/local/bin/winbind_manager.py
RUN chmod +x /entrypoint.sh
RUN chmod 0755 /usr/local/bin/winbind_manager.py \
    && command -v ntlm_auth \
    && command -v net \
    && command -v wbinfo \
    && command -v winbindd

EXPOSE 1812/udp 1813/udp

ENTRYPOINT ["/entrypoint.sh"]
