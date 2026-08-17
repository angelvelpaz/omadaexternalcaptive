#!/bin/sh
echo "[NGINX] Starting reload monitor..."
while true; do
    if [ -f /etc/nginx/ssl/.reload ]; then
        echo "[NGINX] Certificate reload requested. Reloading configuration..."
        cp /etc/nginx/ssl/portal.crt /tmp/portal.crt.previous
        cp /etc/nginx/ssl/portal.key /tmp/portal.key.previous

        if nginx -t; then
            if nginx -s reload; then
                rm -f /etc/nginx/ssl/.reload /tmp/portal.crt.previous /tmp/portal.key.previous
            else
                echo "[NGINX] Reload failed; restoring previous certificates."
                cp /tmp/portal.crt.previous /etc/nginx/ssl/portal.crt
                cp /tmp/portal.key.previous /etc/nginx/ssl/portal.key
                rm -f /etc/nginx/ssl/.reload /tmp/portal.crt.previous /tmp/portal.key.previous
            fi
        else
            echo "[NGINX] Certificate validation failed; restoring previous certificates."
            cp /tmp/portal.crt.previous /etc/nginx/ssl/portal.crt
            cp /tmp/portal.key.previous /etc/nginx/ssl/portal.key
            rm -f /etc/nginx/ssl/.reload /tmp/portal.crt.previous /tmp/portal.key.previous
        fi
    fi
    sleep 2
done
