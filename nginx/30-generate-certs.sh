#!/bin/sh
if [ ! -f /etc/nginx/ssl/portal.crt ] || [ ! -f /etc/nginx/ssl/portal.key ]; then
    echo "[NGINX] Certificate not found. Generating temporary self-signed certificate..."
    mkdir -p /etc/nginx/ssl
    openssl req -x509 -nodes -days 3650 \
      -newkey rsa:2048 \
      -keyout /etc/nginx/ssl/portal.key \
      -out    /etc/nginx/ssl/portal.crt \
      -subj   "/C=EC/ST=Pastaza/L=Puyo/O=Portal Cautivo/CN=captiveportal" \
      -addext "subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:captiveportal"
fi

# Asegurar que el backend (usuario 'node') pueda escribir y crear archivos en esta carpeta
chmod 777 /etc/nginx/ssl
chmod 666 /etc/nginx/ssl/portal.crt /etc/nginx/ssl/portal.key

# Start monitor in the background
/etc/nginx/ssl-reload-monitor.sh &
