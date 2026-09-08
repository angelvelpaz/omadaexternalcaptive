-- IPAM — Esquema de gestión de direccionamiento IP
-- Ejecutado automáticamente por el contenedor PostgreSQL al iniciar

-- ─── Sedes / Ubicaciones ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ipam_sites (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    timezone    VARCHAR(50) DEFAULT 'America/Guayaquil',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Credenciales SNMP ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ipam_snmp_credentials (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(100) UNIQUE NOT NULL,
    snmp_version    VARCHAR(5) NOT NULL DEFAULT '3',
    community       VARCHAR(100),
    security_level  VARCHAR(20),
    username        VARCHAR(100),
    auth_protocol   VARCHAR(10),
    auth_secret     VARCHAR(255),
    priv_protocol   VARCHAR(10),
    priv_secret     VARCHAR(255),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ─── Dispositivos de red ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ipam_network_devices (
    id                SERIAL PRIMARY KEY,
    site_id           INTEGER REFERENCES ipam_sites(id) ON DELETE SET NULL,
    name              VARCHAR(100) NOT NULL,
    hostname          VARCHAR(255),
    management_ip     INET NOT NULL,
    vendor            VARCHAR(50) NOT NULL DEFAULT 'generic',
    model             VARCHAR(100),
    device_type       VARCHAR(30) NOT NULL DEFAULT 'switch',
    enabled           BOOLEAN DEFAULT TRUE,
    snmp_port         INTEGER DEFAULT 161,
    snmp_timeout_ms   INTEGER DEFAULT 5000,
    snmp_retries      INTEGER DEFAULT 2,
    snmp_credential_id INTEGER REFERENCES ipam_snmp_credentials(id) ON DELETE SET NULL,
    last_poll_at      TIMESTAMPTZ,
    last_poll_status  VARCHAR(20),
    last_poll_error   TEXT,
    sys_descr         TEXT,
    sys_uptime        BIGINT,
    trunk_ports       TEXT[],
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    updated_at        TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(management_ip)
);

CREATE INDEX IF NOT EXISTS idx_ipam_devices_vendor ON ipam_network_devices(vendor);
CREATE INDEX IF NOT EXISTS idx_ipam_devices_site ON ipam_network_devices(site_id);

-- ─── VLAN ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ipam_vlans (
    id          SERIAL PRIMARY KEY,
    site_id     INTEGER REFERENCES ipam_sites(id) ON DELETE SET NULL,
    vlan_id     INTEGER NOT NULL CHECK (vlan_id >= 1 AND vlan_id <= 4094),
    name        VARCHAR(100),
    description TEXT,
    network     CIDR,
    gateway     INET,
    dhcp_source VARCHAR(50),
    enabled     BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(site_id, vlan_id)
);

CREATE INDEX IF NOT EXISTS idx_ipam_vlans_vlan_id ON ipam_vlans(vlan_id);

-- ─── Direcciones IP ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ipam_addresses (
    id               SERIAL PRIMARY KEY,
    vlan_id          INTEGER REFERENCES ipam_vlans(id) ON DELETE CASCADE,
    address          INET NOT NULL,
    status           VARCHAR(20) NOT NULL DEFAULT 'available',
    hostname         VARCHAR(255),
    description      TEXT,
    owner            VARCHAR(200),
    mac_address      VARCHAR(17),
    source           VARCHAR(20) DEFAULT 'manual',
    device_id        INTEGER REFERENCES ipam_network_devices(id) ON DELETE SET NULL,
    last_seen_at     TIMESTAMPTZ,
    first_seen_at    TIMESTAMPTZ DEFAULT NOW(),
    lease_expires_at TIMESTAMPTZ,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    updated_at       TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(vlan_id, address)
);

CREATE INDEX IF NOT EXISTS idx_ipam_addresses_mac ON ipam_addresses(mac_address);
CREATE INDEX IF NOT EXISTS idx_ipam_addresses_status ON ipam_addresses(status);
CREATE INDEX IF NOT EXISTS idx_ipam_addresses_vlan ON ipam_addresses(vlan_id);

-- ─── Observaciones (histórico) ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ipam_observations (
    id               SERIAL PRIMARY KEY,
    address_id       INTEGER REFERENCES ipam_addresses(id) ON DELETE CASCADE,
    device_id        INTEGER REFERENCES ipam_network_devices(id) ON DELETE SET NULL,
    ip_address       INET,
    mac_address      VARCHAR(17),
    interface_index  INTEGER,
    interface_name   VARCHAR(100),
    vlan_id          INTEGER,
    source           VARCHAR(20),
    observed_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ipam_obs_address ON ipam_observations(address_id);
CREATE INDEX IF NOT EXISTS idx_ipam_obs_device ON ipam_observations(device_id);
CREATE INDEX IF NOT EXISTS idx_ipam_obs_mac ON ipam_observations(mac_address);
CREATE INDEX IF NOT EXISTS idx_ipam_obs_time ON ipam_observations(observed_at);

-- ─── Ejecuciones de descubrimiento ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ipam_poll_runs (
    id              SERIAL PRIMARY KEY,
    device_id       INTEGER REFERENCES ipam_network_devices(id) ON DELETE CASCADE,
    started_at      TIMESTAMPTZ DEFAULT NOW(),
    finished_at     TIMESTAMPTZ,
    status          VARCHAR(20) DEFAULT 'running',
    records_found   INTEGER DEFAULT 0,
    error           TEXT
);

CREATE INDEX IF NOT EXISTS idx_ipam_poll_device ON ipam_poll_runs(device_id);
CREATE INDEX IF NOT EXISTS idx_ipam_poll_status ON ipam_poll_runs(status);
