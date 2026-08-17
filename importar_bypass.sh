#!/bin/bash
# Script de carga masiva de MAB / PPSK MAC Bypass desde un archivo CSV
# Uso: ./importar_bypass.sh ruta/al/archivo.csv

CSV_FILE=$1

if [ -z "$CSV_FILE" ]; then
  echo "Error: Especifique un archivo CSV. Uso: $0 <archivo.csv>"
  exit 1
fi

if [ ! -f "$CSV_FILE" ]; then
  echo "Error: El archivo especificado no existe o no es un archivo regular: $CSV_FILE"
  exit 1
fi

# Copiar el archivo CSV temporalmente dentro del contenedor
echo "Copiando archivo CSV al contenedor..."
docker compose exec -T portal rm -f /tmp/import.csv
if ! docker cp "$CSV_FILE" captive_portal:/tmp/import.csv; then
  echo "Error: no se pudo copiar el CSV al contenedor captive_portal."
  exit 1
fi

# Ejecutar el script importador dentro del contenedor pasándole las variables de entorno correctas
echo "Ejecutando proceso de importación masiva..."
docker compose exec -T portal node src/scripts/importMacBypass.js /tmp/import.csv

# Guardar código de salida del script
EXIT_CODE=$?

# Limpiar archivo temporal en el contenedor
docker compose exec -T -u root portal rm -f /tmp/import.csv

if [ $EXIT_CODE -eq 0 ]; then
  echo "Proceso finalizado."
else
  echo "Hubo errores durante el proceso de importación masiva."
fi

exit $EXIT_CODE
