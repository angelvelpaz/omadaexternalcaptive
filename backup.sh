#!/bin/bash
# Script de Backup para el Portal Cautivo

# Directorio de destino para los backups
BACKUP_DIR="./backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_NAME="backup_captiveportal_${TIMESTAMP}"
TEMP_DIR="/tmp/${BACKUP_NAME}"

# Colores para salida de terminal
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # Sin color

echo -e "${BLUE}=== Iniciando Respaldo del Sistema del Portal Cautivo ===${NC}"

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

# Crear directorios temporales y de destino
mkdir -p "${BACKUP_DIR}"
mkdir -p "${TEMP_DIR}"

# 1. Respaldo de la Base de Datos PostgreSQL
echo -e "${YELLOW}[1/4] Realizando volcado de la base de datos PostgreSQL...${NC}"
docker compose exec -T postgres pg_dump -U "${POSTGRES_USER}" "${POSTGRES_DB}" > "${TEMP_DIR}/database_dump.sql"

if [ $? -eq 0 ]; then
  echo -e "${GREEN}✓ Volcado de base de datos completado con éxito.${NC}"
else
  echo -e "${RED}Error al exportar la base de datos.${NC}"
  rm -rf "${TEMP_DIR}"
  exit 1
fi

# 2. Respaldo del archivo de configuración de entorno (.env)
echo -e "${YELLOW}[2/4] Respaldando archivo .env...${NC}"
cp .env "${TEMP_DIR}/.env.backup"

# 3. Respaldo de los directorios de configuración de los servicios
echo -e "${YELLOW}[3/4] Copiando archivos de configuración de servicios (nginx, freeradius, ssl)...${NC}"
mkdir -p "${TEMP_DIR}/config"
cp -r nginx freeradius ssl "${TEMP_DIR}/config/" 2>/dev/null || true

# 4. Empaquetar todo en un archivo comprimido .tar.gz
echo -e "${YELLOW}[4/4] Comprimiendo archivos de respaldo...${NC}"
tar -czf "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz" -C "/tmp" "${BACKUP_NAME}"

if [ $? -eq 0 ]; then
  echo -e "${GREEN}✓ Archivo comprimido creado: ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz${NC}"
  # Limpieza de archivos temporales
  rm -rf "${TEMP_DIR}"
  echo -e "${GREEN}=== Respaldo finalizado con éxito ===${NC}"
  echo -e "${BLUE}Puedes descargar el archivo o copiarlo a una ubicación externa segura.${NC}"
else
  echo -e "${RED}Error al comprimir el respaldo.${NC}"
  rm -rf "${TEMP_DIR}"
  exit 1
fi
