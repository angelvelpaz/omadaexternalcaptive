'use strict';

const { getPool } = require('./pool');

// ─── Admin: Grupos RADIUS ─────────────────────────────────────────────────────

/**
 * Lista todos los grupos con sus atributos de respuesta.
 */
async function listGroups() {
  const groups = await getPool().query(
    `SELECT DISTINCT groupname FROM radgroupreply ORDER BY groupname`
  );

  const attrs = await getPool().query(
    `SELECT id, groupname, attribute, op, value FROM radgroupreply ORDER BY groupname, id`
  );

  // Contar usuarios por grupo
  const counts = await getPool().query(
    `SELECT groupname, COUNT(*) as total FROM radusergroup GROUP BY groupname`
  );
  const countMap = {};
  counts.rows.forEach(r => { countMap[r.groupname] = parseInt(r.total); });

  const attrsByGroup = {};
  attrs.rows.forEach(r => {
    if (!attrsByGroup[r.groupname]) attrsByGroup[r.groupname] = [];
    attrsByGroup[r.groupname].push(r);
  });

  return groups.rows.map(g => ({
    groupname: g.groupname,
    userCount: countMap[g.groupname] || 0,
    attributes: attrsByGroup[g.groupname] || [],
  }));
}

/**
 * Agrega un atributo a un grupo.
 */
async function addGroupAttribute({ groupname, attribute, op, value }) {
  const result = await getPool().query(
    `INSERT INTO radgroupreply (groupname, attribute, op, value)
     VALUES ($1, $2, $3, $4) RETURNING *`,
    [groupname, attribute, op, value]
  );
  return result.rows[0];
}

/**
 * Elimina un atributo de grupo por ID.
 */
async function deleteGroupAttribute(id) {
  await getPool().query(`DELETE FROM radgroupreply WHERE id = $1`, [id]);
}

/**
 * Elimina un grupo completo y desvincula usuarios.
 */
async function deleteGroup(groupname) {
  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    await client.query(`DELETE FROM radgroupreply  WHERE groupname = $1`, [groupname]);
    await client.query(`DELETE FROM radgroupcheck  WHERE groupname = $1`, [groupname]);
    await client.query(`DELETE FROM radusergroup   WHERE groupname = $1`, [groupname]);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = {
  listGroups,
  addGroupAttribute,
  deleteGroupAttribute,
  deleteGroup,
};
