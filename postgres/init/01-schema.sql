-- Portal Cautivo — Schema de base de datos
-- Ejecutado automáticamente por el contenedor PostgreSQL al iniciar

-- ─── Tabla de usuarios del portal ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS usuarios_portal (
    id                     SERIAL PRIMARY KEY,
    cedula                 VARCHAR(10) UNIQUE NOT NULL,
    nombres                VARCHAR(100) NOT NULL,
    apellidos              VARCHAR(100) NOT NULL,
    email                  VARCHAR(150) NOT NULL,
    radius_password        VARCHAR(36) NOT NULL,
    fecha_registro         TIMESTAMPTZ DEFAULT NOW(),
    activo                 BOOLEAN DEFAULT TRUE,
    acepta_terminos        BOOLEAN NOT NULL DEFAULT TRUE,
    fecha_acepta_terminos  TIMESTAMPTZ DEFAULT NOW(),
    max_dispositivos       INTEGER DEFAULT 1,
    terminos_aceptados     TEXT
);

CREATE INDEX IF NOT EXISTS idx_usuarios_portal_cedula ON usuarios_portal(cedula);
CREATE INDEX IF NOT EXISTS idx_usuarios_portal_email ON usuarios_portal(email);

-- ─── Tablas FreeRADIUS (rlm_sql) ─────────────────────────────────────────────
-- Los nombres de columnas deben coincidir exactamente con la config de rlm_sql

CREATE TABLE IF NOT EXISTS radcheck (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(64) NOT NULL DEFAULT '',
    attribute   VARCHAR(64) NOT NULL DEFAULT '',
    op          CHAR(2)     NOT NULL DEFAULT '==',
    value       VARCHAR(253) NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS radcheck_username ON radcheck(username, attribute);

CREATE TABLE IF NOT EXISTS radreply (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(64) NOT NULL DEFAULT '',
    attribute   VARCHAR(64) NOT NULL DEFAULT '',
    op          CHAR(2)     NOT NULL DEFAULT '=',
    value       VARCHAR(253) NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS radreply_username ON radreply(username, attribute);

CREATE TABLE IF NOT EXISTS radgroupcheck (
    id          SERIAL PRIMARY KEY,
    groupname   VARCHAR(64) NOT NULL DEFAULT '',
    attribute   VARCHAR(64) NOT NULL DEFAULT '',
    op          CHAR(2)     NOT NULL DEFAULT '==',
    value       VARCHAR(253) NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS radgroupcheck_groupname ON radgroupcheck(groupname, attribute);

CREATE TABLE IF NOT EXISTS radgroupreply (
    id          SERIAL PRIMARY KEY,
    groupname   VARCHAR(64) NOT NULL DEFAULT '',
    attribute   VARCHAR(64) NOT NULL DEFAULT '',
    op          CHAR(2)     NOT NULL DEFAULT '=',
    value       VARCHAR(253) NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS radgroupreply_groupname ON radgroupreply(groupname, attribute);

CREATE TABLE IF NOT EXISTS radusergroup (
    username    VARCHAR(64) NOT NULL DEFAULT '',
    groupname   VARCHAR(64) NOT NULL DEFAULT '',
    priority    INTEGER     NOT NULL DEFAULT 0,
    PRIMARY KEY (username, groupname)
);
CREATE INDEX IF NOT EXISTS radusergroup_username ON radusergroup(username);

-- Tabla de accounting de sesiones RADIUS
CREATE TABLE IF NOT EXISTS radacct (
    radacctid           BIGSERIAL PRIMARY KEY,
    acctsessionid       VARCHAR(64)  NOT NULL DEFAULT '',
    acctuniqueid        VARCHAR(32)  NOT NULL DEFAULT '' UNIQUE,
    username            VARCHAR(64)  NOT NULL DEFAULT '',
    realm               VARCHAR(64)  DEFAULT '',
    nasipaddress        INET         NOT NULL DEFAULT '0.0.0.0',
    nasportid           VARCHAR(15)  DEFAULT NULL,
    nasporttype         VARCHAR(32)  DEFAULT NULL,
    acctstarttime       TIMESTAMPTZ  DEFAULT NULL,
    acctupdatetime      TIMESTAMPTZ  DEFAULT NULL,
    acctstoptime        TIMESTAMPTZ  DEFAULT NULL,
    acctinterval        BIGINT       DEFAULT NULL,
    acctsessiontime     BIGINT       DEFAULT NULL,
    acctauthentic       VARCHAR(32)  DEFAULT NULL,
    connectinfo_start   VARCHAR(50)  DEFAULT NULL,
    connectinfo_stop    VARCHAR(50)  DEFAULT NULL,
    acctinputoctets     BIGINT       DEFAULT NULL,
    acctoutputoctets    BIGINT       DEFAULT NULL,
    calledstationid     VARCHAR(50)  NOT NULL DEFAULT '',
    callingstationid    VARCHAR(50)  NOT NULL DEFAULT '',
    acctterminatecause  VARCHAR(32)  DEFAULT '',
    servicetype         VARCHAR(32)  DEFAULT NULL,
    framedprotocol      VARCHAR(32)  DEFAULT NULL,
    framedipaddress     INET         DEFAULT NULL,
    framedipv6address   INET         DEFAULT NULL,
    framedipv6prefix    INET         DEFAULT NULL,
    framedinterfaceid   VARCHAR(44)  DEFAULT NULL,
    delegatedipv6prefix INET         DEFAULT NULL,
    class               VARCHAR(253) DEFAULT NULL,
    proto               VARCHAR(6)   DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS radacct_username        ON radacct(username);
CREATE INDEX IF NOT EXISTS radacct_starttime       ON radacct(acctstarttime);
CREATE INDEX IF NOT EXISTS radacct_nasipaddress    ON radacct(nasipaddress);
CREATE INDEX IF NOT EXISTS radacct_acctuniqueid    ON radacct(acctuniqueid);
CREATE INDEX IF NOT EXISTS radacct_acctsessionid   ON radacct(acctsessionid);

-- ─── Tabla de registro de accesos (auditoría) ────────────────────────────────
CREATE TABLE IF NOT EXISTS access_log (
    id          SERIAL PRIMARY KEY,
    cedula      VARCHAR(10) NOT NULL,
    vendor      VARCHAR(20),
    mac_address VARCHAR(17),
    ip_address  INET,
    resultado   VARCHAR(20) NOT NULL,  -- 'success', 'failed', 'registered'
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_access_log_cedula     ON access_log(cedula);
CREATE INDEX IF NOT EXISTS idx_access_log_created_at ON access_log(created_at);

-- ─── Tabla de dispositivos registrados por usuario ───────────────────────────
CREATE TABLE IF NOT EXISTS dispositivos_usuario (
    id          SERIAL PRIMARY KEY,
    cedula      VARCHAR(10) NOT NULL REFERENCES usuarios_portal(cedula) ON DELETE CASCADE,
    mac_address VARCHAR(17) NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(cedula, mac_address)
);

CREATE INDEX IF NOT EXISTS idx_dispositivos_usuario_cedula ON dispositivos_usuario(cedula);
CREATE INDEX IF NOT EXISTS idx_dispositivos_usuario_mac ON dispositivos_usuario(mac_address);

