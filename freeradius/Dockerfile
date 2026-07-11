FROM freeradius/freeradius-server:latest-3.2

# Instalar envsubst (gettext) para sustitución de variables en config
USER root
RUN apt-get update && apt-get install -y --no-install-recommends gettext-base \
    && rm -rf /var/lib/apt/lists/*

# Copiar configuración con plantillas
COPY config/ /etc/raddb/

# Habilitar módulo SQL (crear symlink)
RUN ln -sf /etc/raddb/mods-available/sql /etc/raddb/mods-enabled/sql \
    && chown -R freerad:freerad /etc/raddb

# Script de entrada que sustituye variables y arranca freeradius
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 1812/udp 1813/udp

ENTRYPOINT ["/entrypoint.sh"]
