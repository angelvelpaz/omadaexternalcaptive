-- Migración 003: Agregar columna auth_type a la tabla dispositivos_usuario
-- Fecha: 2026-08-20

ALTER TABLE dispositivos_usuario 
ADD COLUMN IF NOT EXISTS auth_type VARCHAR(20) DEFAULT 'autoregistro';
