-- Migración 002: Cambiar límite predeterminado de WPA Enterprise a 1
-- Fecha: 2026-08-19

-- 1. Modificar el valor por defecto para futuros inserts
ALTER TABLE usuarios_portal ALTER COLUMN max_dispositivos_wpa SET DEFAULT 1;

-- 2. Actualizar los usuarios existentes que tienen valor 0 (ilimitado)
UPDATE usuarios_portal SET max_dispositivos_wpa = 1 WHERE max_dispositivos_wpa = 0;
