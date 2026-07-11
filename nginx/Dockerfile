FROM nginx:1.27-alpine

RUN apk add --no-cache openssl

COPY 30-generate-certs.sh /docker-entrypoint.d/30-generate-certs.sh
RUN chmod +x /docker-entrypoint.d/30-generate-certs.sh

COPY ssl-reload-monitor.sh /etc/nginx/ssl-reload-monitor.sh
RUN chmod +x /etc/nginx/ssl-reload-monitor.sh

COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80 443
