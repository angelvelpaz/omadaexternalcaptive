'use strict';

const { getPool } = require('./pool');

async function listLdapGroupVlans() {
  const result = await getPool().query('SELECT * FROM ldap_group_vlans ORDER BY id ASC');
  return result.rows;
}

async function createLdapGroupVlan(groupDn, vlanId) {
  const result = await getPool().query(
    'INSERT INTO ldap_group_vlans (group_dn, vlan_id) VALUES ($1, $2) ON CONFLICT (group_dn) DO UPDATE SET vlan_id = EXCLUDED.vlan_id RETURNING *',
    [groupDn.trim(), parseInt(vlanId)]
  );
  return result.rows[0];
}

async function deleteLdapGroupVlan(id) {
  const result = await getPool().query('DELETE FROM ldap_group_vlans WHERE id = $1 RETURNING *', [id]);
  return result.rows[0];
}

async function getUsersLocalStatus(usernames) {
  if (!usernames || usernames.length === 0) return [];
  const result = await getPool().query(
    'SELECT cedula, activo FROM usuarios_portal WHERE LOWER(cedula) = ANY($1)',
    [usernames]
  );
  return result.rows;
}

module.exports = {
  listLdapGroupVlans,
  createLdapGroupVlan,
  deleteLdapGroupVlan,
  getUsersLocalStatus,
};
