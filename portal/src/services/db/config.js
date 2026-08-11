'use strict';

const { getPool } = require('./pool');

async function getControllerConfig(vendor) {
  const result = await getPool().query(
    'SELECT config FROM controller_config WHERE vendor = $1',
    [vendor]
  );
  return result.rows[0]?.config || null;
}

async function saveControllerConfig(vendor, config) {
  await getPool().query(
    `INSERT INTO controller_config (vendor, config, updated_at)
     VALUES ($1, $2, NOW())
     ON CONFLICT (vendor) DO UPDATE SET config = EXCLUDED.config, updated_at = NOW()`,
    [vendor, JSON.stringify(config)]
  );
}

async function getSsidConfig(ssidName) {
  const result = await getPool().query(
    'SELECT auth_type, config FROM ssid_config WHERE ssid_name = $1 LIMIT 1',
    [ssidName]
  );
  return result.rows[0] || null;
}

async function saveSsidConfig(ssidName, authType, config) {
  await getPool().query(
    `INSERT INTO ssid_config (ssid_name, auth_type, config, updated_at)
     VALUES ($1, $2, $3, NOW())
     ON CONFLICT (ssid_name) DO UPDATE 
     SET auth_type = EXCLUDED.auth_type, config = EXCLUDED.config, updated_at = NOW()`,
    [ssidName, authType, typeof config === 'object' ? JSON.stringify(config) : config]
  );
}

async function listAllSsidConfigs() {
  const result = await getPool().query(
    'SELECT id, ssid_name, auth_type, config, updated_at FROM ssid_config ORDER BY ssid_name ASC'
  );
  return result.rows;
}

async function deleteSsidConfig(ssidName) {
  await getPool().query(
    'DELETE FROM ssid_config WHERE ssid_name = $1',
    [ssidName]
  );
}

module.exports = {
  getControllerConfig,
  saveControllerConfig,
  getSsidConfig,
  saveSsidConfig,
  listAllSsidConfigs,
  deleteSsidConfig,
};
