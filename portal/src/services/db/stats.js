'use strict';

const { getPool } = require('./pool');

// ─── Admin: Estadísticas Simplificadas (Conexiones Activas en Tiempo Real) ──────

async function getStats() {
  const result = await getPool().query(`
    SELECT 
      COALESCE(u.tipo_usuario, 'mac_bypass') AS tipo,
      COUNT(DISTINCT r.callingstationid)::integer AS total_activos
    FROM radacct r
    LEFT JOIN usuarios_portal u ON u.radius_username = r.username
    WHERE r.acctstoptime IS NULL
    GROUP BY COALESCE(u.tipo_usuario, 'mac_bypass')
  `);

  const activeByType = {
    autoregistro: 0,
    ldap_portal: 0,
    wpa_enterprise: 0,
    hotel: 0,
    restaurant: 0,
    mac_bypass: 0
  };

  result.rows.forEach(row => {
    if (activeByType[row.tipo] !== undefined) {
      activeByType[row.tipo] = row.total_activos;
    }
  });

  const totalActivos = Object.values(activeByType).reduce((a, b) => a + b, 0);

  return {
    totalActivos,
    activeByType
  };
}

module.exports = {
  getStats,
};
