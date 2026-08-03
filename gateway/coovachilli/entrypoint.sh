#!/bin/sh
set -e

if [ -z "$WAN_IF" ] || [ -z "$LAN_IF" ]; then
    echo "ERROR: WAN_IF or LAN_IF environment variables are not defined."
    exit 1
fi

echo "=========================================================="
echo " Starting CoovaChilli Gateway Container                   "
echo " WAN Interface: $WAN_IF"
echo " LAN Interface: $LAN_IF"
echo "=========================================================="

# 1. Asegurar que IP Forwarding está activo en el host
# Nota: require privilegios NET_ADMIN / privileged
echo 1 > /proc/sys/net/ipv4/ip_forward || true

# 2. Configurar reglas de enrutamiento IPTables (Masquerade)
iptables -t nat -D POSTROUTING -o "$WAN_IF" -j MASQUERADE 2>/dev/null || true
iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE

# 3. Generar la configuración de CoovaChilli de forma dinámica
# Se utiliza la IP local del router como GATEWAY_LAN_IP y su red como GATEWAY_LAN_NET
LAN_IP="${GATEWAY_LAN_IP:-192.168.100.1}"
LAN_NET="${GATEWAY_LAN_NET:-192.168.100.0/24}"
UAM_SERVER="${PORTAL_URL:-http://captive.pastaza.gob.ec/}"
RADIUS_IP="${RADIUS_HOST:-127.0.0.1}"
SECRET="${RADIUS_SECRET:-shared_secret_muy_seguro}"
UAM_SECRET="${GATEWAY_UAM_SECRET:-uam_secret_compartido_seguro}"

echo "Generando /etc/chilli.conf..."
cat <<EOF > /etc/chilli.conf
# Interfaces
dhcpif=$LAN_IF
extif=$WAN_IF

# Configuración de Red IP y DHCP
net=$LAN_NET
uamlisten=$LAN_IP
dynipstart=10
dynipend=250

# Servidores DNS entregados a clientes
dns1=8.8.8.8
dns2=8.8.4.4

# Servidores RADIUS
radiusserver1=$RADIUS_IP
radiusserver2=$RADIUS_IP
radiussecret=$SECRET
radport=1812
acctport=1813
coaport=3799

# Redirección de Portal Cautivo (UAM)
uamserver=$UAM_SERVER
uamhomepage=$UAM_SERVER
uamsecret=$UAM_SECRET

# Walled Garden básico (Separado por comas)
uamallowed=captive.pastaza.gob.ec,192.168.122.1,8.8.8.8
EOF

# 4. Iniciar CoovaChilli en primer plano (foreground)
exec chilli --fg --debug
