#!/bin/sh
if [ ! -f /etc/nginx/ssl/portal.crt ] || [ ! -f /etc/nginx/ssl/portal.key ]; then
    echo "[NGINX] Certificate not found. Generating temporary self-signed certificate..."
    mkdir -p /etc/nginx/ssl
    openssl req -x509 -nodes -days 3650 \
      -newkey rsa:2048 \
      -keyout /etc/nginx/ssl/portal.key \
      -out    /etc/nginx/ssl/portal.crt \
      -subj   "/C=EC/ST=State/L=City/O=Portal Cautivo/CN=captiveportal" \
      -addext "subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:captiveportal"
fi

# El portal escribe certificados mediante el volumen compartido; Nginx solo
# necesita leerlos. El UID 1000 corresponde al usuario node de la imagen portal.
chown 1000:0 /etc/nginx/ssl 2>/dev/null || true
chmod 750 /etc/nginx/ssl
chown 1000:0 /etc/nginx/ssl/portal.crt /etc/nginx/ssl/portal.key 2>/dev/null || true
chmod 640 /etc/nginx/ssl/portal.crt /etc/nginx/ssl/portal.key

# Start monitor in the background
/etc/nginx/ssl-reload-monitor.sh &
