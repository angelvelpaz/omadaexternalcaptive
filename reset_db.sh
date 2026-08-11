#!/bin/bash
# Script para encerar (vaciar) la base de datos del Portal Cautivo

# Colores para salida de terminal
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # Sin color

echo -e "${RED}=================================================================${NC}"
echo -e "${RED}⚠️  PELIGRO: ESTA OPERACIÓN ELIMINARÁ DATOS DE LA BASE DE DATOS  ⚠️${NC}"
echo -e "${RED}=================================================================${NC}"

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

echo -e "${YELLOW}Este script limpiará las tablas de transacciones, logs y usuarios del Portal Cautivo.${NC}"
echo -e "Las configuraciones de SSIDs, LDAP y marcas (branding) se preservarán."
echo ""
read -p "¿Está seguro de que desea encerar la base de datos? (escriba 'SI' en mayúsculas para proceder): " CONFIRM

if [ "$CONFIRM" != "SI" ]; then
  echo -e "${BLUE}Operación cancelada por el usuario.${NC}"
  exit 0
fi

echo -e "\n${YELLOW}[1/3] Realizando backup de seguridad rápido antes de encerar...${NC}"
mkdir -p ./backups
BACKUP_FILE="./backups/pre_reset_backup_$(date +%Y%m%d_%H%M%S).sql"
docker compose exec -T postgres pg_dump -U "${POSTGRES_USER}" "${POSTGRES_DB}" > "${BACKUP_FILE}"

if [ $? -eq 0 ]; then
  echo -e "${GREEN}✓ Respaldo de seguridad creado en: ${BACKUP_FILE}${NC}"
else
  echo -e "${RED}Error al crear el respaldo de seguridad. Abortando operación por seguridad.${NC}"
  exit 1
fi

echo -e "\n${YELLOW}[2/3] Vaciando tablas en la base de datos PostgreSQL...${NC}"

# Comando SQL para truncar las tablas dinámicas y de logs restableciendo las secuencias
SQL_COMMAND="
BEGIN;
TRUNCATE TABLE radacct RESTART IDENTITY CASCADE;
TRUNCATE TABLE access_log RESTART IDENTITY CASCADE;
TRUNCATE TABLE auditoria_admin RESTART IDENTITY CASCADE;
TRUNCATE TABLE admin_sessions RESTART IDENTITY CASCADE;
TRUNCATE TABLE dispositivos_usuario RESTART IDENTITY CASCADE;
TRUNCATE TABLE usuarios_portal RESTART IDENTITY CASCADE;
TRUNCATE TABLE hotel_guests RESTART IDENTITY CASCADE;
TRUNCATE TABLE restaurant_pins RESTART IDENTITY CASCADE;
TRUNCATE TABLE mac_bypass RESTART IDENTITY CASCADE;
TRUNCATE TABLE radcheck RESTART IDENTITY CASCADE;
TRUNCATE TABLE radusergroup RESTART IDENTITY CASCADE;
TRUNCATE TABLE radreply RESTART IDENTITY CASCADE;
COMMIT;
"

# Ejecutar el comando SQL dentro del contenedor de postgres
docker compose exec -T postgres psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -c "${SQL_COMMAND}"

if [ $? -eq 0 ]; then
  echo -e "${GREEN}✓ Limpieza de usuarios y registros completada.${NC}"
else
  echo -e "${RED}Error al ejecutar la limpieza de base de datos.${NC}"
  exit 1
fi

echo -e "\n${YELLOW}[3/3] Gestión de contraseña del administrador principal ('admin')...${NC}"
read -p "¿Desea cambiar la contraseña del usuario 'admin'? (S/N): " CHANGE_PWD

if [[ "$CHANGE_PWD" =~ ^[Ss]$ ]]; then
  # Leer contraseña ocultando los caracteres introducidos
  read -s -p "Ingrese la nueva contraseña para 'admin': " NEW_PWD
  echo ""
  read -s -p "Confirme la nueva contraseña: " NEW_PWD_CONFIRM
  echo ""
  
  if [ "$NEW_PWD" != "$NEW_PWD_CONFIRM" ]; then
    echo -e "${RED}Error: Las contraseñas no coinciden. Se mantendrá la contraseña actual.${NC}"
  elif [ -z "$NEW_PWD" ]; then
    echo -e "${RED}Error: La contraseña no puede estar vacía. Se mantendrá la contraseña actual.${NC}"
  else
    echo -e "${YELLOW}Generando hash y actualizando base de datos...${NC}"
    
    # Generar el hash PBKDF2 en el contenedor de NodeJS usando las mismas funciones que la app
    PWD_HASH=$(docker compose exec -T portal node -e "
      const crypto = require('crypto');
      const pwd = process.argv[1];
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = crypto.pbkdf2Sync(pwd, salt, 1000, 64, 'sha512').toString('hex');
      console.log(salt + ':' + hash);
    " "$NEW_PWD")
    
    if [ $? -eq 0 ] && [ ! -z "$PWD_HASH" ]; then
      # Actualizar en la base de datos PostgreSQL
      docker compose exec -T postgres psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -c "UPDATE administradores SET password_hash = '${PWD_HASH}', activo = TRUE WHERE username = 'admin';" >/dev/null
      
      if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Contraseña del administrador 'admin' actualizada exitosamente.${NC}"
      else
        echo -e "${RED}Error al actualizar la contraseña en la base de datos.${NC}"
      fi
    else
      echo -e "${RED}Error al generar el hash criptográfico de la contraseña.${NC}"
    fi
  fi
else
  echo -e "${BLUE}Se mantiene la contraseña actual del usuario 'admin'.${NC}"
fi

echo -e "\n${GREEN}=== Proceso finalizado con éxito ===${NC}"
