#!/bin/sh
echo "[NGINX] Starting reload monitor..."
while true; do
    if [ -f /etc/nginx/ssl/.reload ]; then
        echo "[NGINX] Certificate reload requested. Reloading configuration..."
        rm -f /etc/nginx/ssl/.reload
        nginx -s reload
    fi
    sleep 2
done
