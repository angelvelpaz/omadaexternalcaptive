#!/bin/bash
# Script para restablecer la contraseña de un usuario administrador del Portal Cautivo

# Colores para salida de terminal
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # Sin color

echo -e "${BLUE}=== Restablecer Contraseña de Administrador ===${NC}"

# Cargar variables de entorno necesarias del archivo .env
if [ -f .env ]; then
  POSTGRES_USER=$(grep -E "^POSTGRES_USER=" .env | cut -d'=' -f2- | tr -d '"' | tr -d "'")
  POSTGRES_DB=$(grep -E "^POSTGRES_DB=" .env | cut -d'=' -f2- | tr -d '"' | tr -d "'")
  
  if [ -z "$POSTGRES_USER" ] || [ -z "$POSTGRES_DB" ]; then
    echo -e "${RED}Error: POSTGRES_USER o POSTGRES_DB no definidos en el archivo .env.${NC}"
    exit 1
  fi
else
  echo -e "${RED}Error: Archivo .env no encontrado en el directorio actual.${NC}"
  exit 1
fi

# Verificar si los contenedores necesarios están corriendo
if [ -z "$(docker ps -q -f name=captive_portal)" ]; then
  echo -e "${RED}Error: El contenedor 'captive_portal' debe estar corriendo para generar el hash de la contraseña.${NC}"
  exit 1
fi

if [ -z "$(docker ps -q -f name=captive_postgres)" ]; then
  echo -e "${RED}Error: El contenedor 'captive_postgres' debe estar corriendo para actualizar la base de datos.${NC}"
  exit 1
fi

# Solicitar el nombre de usuario del administrador
read -p "Ingrese el nombre de usuario administrador [admin]: " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}

# Validar si el usuario existe en la base de datos
USER_EXISTS=$(docker compose exec -T postgres psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -v admin_user="$ADMIN_USER" -t -A -c "SELECT COUNT(1) FROM administradores WHERE username = :'admin_user';")

if [ "$USER_EXISTS" != "1" ]; then
  echo -e "${RED}Error: El usuario administrador '${ADMIN_USER}' no existe en la base de datos.${NC}"
  exit 1
fi

# Solicitar la nueva contraseña
read -s -p "Ingrese la nueva contraseña para '${ADMIN_USER}': " NEW_PWD
echo ""
read -s -p "Confirme la nueva contraseña: " NEW_PWD_CONFIRM
echo ""

if [ "$NEW_PWD" != "$NEW_PWD_CONFIRM" ]; then
  echo -e "${RED}Error: Las contraseñas no coinciden. Intente de nuevo.${NC}"
  exit 1
fi

if [ -z "$NEW_PWD" ]; then
  echo -e "${RED}Error: La contraseña no puede estar vacía.${NC}"
  exit 1
fi

echo -e "${YELLOW}Generando hash PBKDF2 seguro...${NC}"

# Generar el hash utilizando la lógica de Node.js de la aplicación para garantizar compatibilidad
PWD_HASH=$(docker compose exec -T portal node -e "
  const crypto = require('crypto');
  const pwd = process.argv[1];
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(pwd, salt, 1000, 64, 'sha512').toString('hex');
  console.log(salt + ':' + hash);
" "$NEW_PWD")

if [ $? -ne 0 ] || [ -z "$PWD_HASH" ]; then
  echo -e "${RED}Error al generar el hash criptográfico de la contraseña.${NC}"
  exit 1
fi

# Actualizar el hash en la base de datos
echo -e "${YELLOW}Actualizando la base de datos...${NC}"
docker compose exec -T postgres psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" \
  -v admin_user="$ADMIN_USER" -v pwd_hash="$PWD_HASH" \
  -c "UPDATE administradores SET password_hash = :'pwd_hash', activo = TRUE WHERE username = :'admin_user';" >/dev/null

if [ $? -eq 0 ]; then
  echo -e "${GREEN}✓ La contraseña del administrador '${ADMIN_USER}' ha sido restablecida exitosamente.${NC}"
  echo -e "${BLUE}=== Proceso finalizado con éxito ===${NC}"
else
  echo -e "${RED}Error al actualizar el registro en la base de datos PostgreSQL.${NC}"
  exit 1
fi
