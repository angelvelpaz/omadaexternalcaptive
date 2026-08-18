-- Migración 001: Agregar columnas para WPA Enterprise y bloqueo de usuarios
-- Fecha: 2026-08-18

-- Columna max_dispositivos_wpa para límite de dispositivos WPA Enterprise
ALTER TABLE usuarios_portal ADD COLUMN IF NOT EXISTS max_dispositivos_wpa INTEGER DEFAULT 0;

-- Columna bloqueado para rechazo total en FreeRADIUS (Auth-Type := Reject)
ALTER TABLE usuarios_portal ADD COLUMN IF NOT EXISTS bloqueado BOOLEAN DEFAULT FALSE;

-- Tabla de dispositivos WPA Enterprise registrados
CREATE TABLE IF NOT EXISTS wpa_enterprise_devices (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(64) NOT NULL,
    mac_address VARCHAR(17) NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(username, mac_address)
);
CREATE INDEX IF NOT EXISTS idx_wpa_ent_devices_username ON wpa_enterprise_devices(username);

-- Sincronizar bloqueado con estado de activación existente
UPDATE usuarios_portal SET bloqueado = NOT activo WHERE activo = FALSE;
