FROM alpine:3.18
RUN apk add --no-cache coova-chilli iptables openssl tini

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
