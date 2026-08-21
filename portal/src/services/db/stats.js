'use strict';

const { getPool } = require('./pool');
const { getVendor } = require('mac-oui-lookup');

// ─── Admin: Estadísticas ──────────────────────────────────────────────────────

function cleanVendorName(rawName) {
  if (!rawName) return 'Genérico / Privado';
  const name = rawName.toLowerCase();
  if (name.includes('apple')) return 'Apple';
  if (name.includes('samsung')) return 'Samsung';
  if (name.includes('huawei')) return 'Huawei';
  if (name.includes('xiaomi') || name.includes('chongqing chimi') || name.includes('beijing xiaomi')) return 'Xiaomi';
  if (name.includes('motorola') || name.includes('lenovo')) return 'Motorola/Lenovo';
  if (name.includes('tp-link') || name.includes('shenzhen tp-link')) return 'TP-Link';
  if (name.includes('intel')) return 'Intel';
  if (name.includes('lg electronics') || name.includes('lg ')) return 'LG';
  if (name.includes('oppo') || name.includes('guangdong oppo')) return 'Oppo';
  if (name.includes('vivo mobile')) return 'Vivo';
  if (name.includes('realme')) return 'Realme';
  if (name.includes('oneplus')) return 'OnePlus';
  if (name.includes('zte')) return 'ZTE';
  if (name.includes('nokia')) return 'Nokia';
  if (name.includes('sony')) return 'Sony';
  if (name.includes('google')) return 'Google';
  if (name.includes('amazon')) return 'Amazon';
  if (name.includes('hmd global')) return 'Nokia';
  if (name.includes('asus')) return 'Asus';
  if (name.includes('hp ') || name.includes('hewlett-packard')) return 'HP';
  if (name.includes('dell')) return 'Dell';
  
  return rawName.split(',')[0].split(';')[0].trim();
}

async function getStats() {
  const [totals, today, byVendor, byResult, recentLogs, allMacs] = await Promise.all([
    getPool().query(`
      SELECT
        COUNT(*) FILTER (WHERE activo = TRUE)  AS active_users,
        COUNT(*) FILTER (WHERE activo = FALSE) AS inactive_users,
        COUNT(*)                               AS total_users,
        COUNT(*) FILTER (WHERE tipo_usuario = 'ldap_portal') AS institutional_users,
        COUNT(*) FILTER (WHERE tipo_usuario = 'autoregistro' OR tipo_usuario = 'externo' OR tipo_usuario = 'institucional') AS external_users,
        COUNT(*) FILTER (WHERE tipo_usuario = 'wpa_enterprise') AS wpa_enterprise_users,
        COUNT(*) FILTER (WHERE tipo_usuario = 'hotel')          AS hotel_users,
        COUNT(*) FILTER (WHERE tipo_usuario = 'restaurant')     AS restaurant_users
      FROM usuarios_portal
    `),
    getPool().query(`
      SELECT COUNT(*) AS today_logins
      FROM access_log a
      JOIN usuarios_portal u ON u.cedula = a.cedula
      WHERE a.created_at >= CURRENT_DATE AND a.resultado IN ('success', 'registered')
    `),
    getPool().query(`
      SELECT a.vendor, COUNT(*) AS total
      FROM access_log a
      JOIN usuarios_portal u ON u.cedula = a.cedula
      WHERE a.created_at >= NOW() - INTERVAL '7 days' AND a.resultado IN ('success', 'registered')
      GROUP BY a.vendor ORDER BY total DESC
    `),
    getPool().query(`
      SELECT a.resultado, COUNT(*) AS total
      FROM access_log a
      JOIN usuarios_portal u ON u.cedula = a.cedula
      WHERE a.created_at >= NOW() - INTERVAL '7 days'
      GROUP BY a.resultado
    `),
    getPool().query(`
      SELECT a.cedula, u.nombres, u.apellidos, a.vendor, a.resultado, a.created_at
      FROM access_log a
      JOIN usuarios_portal u ON u.cedula = a.cedula
      ORDER BY a.created_at DESC LIMIT 10
    `),
    getPool().query(`
      SELECT mac_address AS callingstationid
      FROM dispositivos_usuario
      ORDER BY created_at DESC
      LIMIT 100
    `),
  ]);

  const brandCounts = {};
  for (const row of allMacs.rows) {
    if (!row.callingstationid) continue;
    const rawVendor = getVendor(row.callingstationid);
    const brand = cleanVendorName(rawVendor);
    brandCounts[brand] = (brandCounts[brand] || 0) + 1;
  }

  const topBrands = Object.entries(brandCounts)
    .map(([brand, count]) => ({ brand, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  return {
    ...totals.rows[0],
    todayLogins: parseInt(today.rows[0].today_logins),
    byVendor: byVendor.rows,
    byResult: byResult.rows,
    recentLogs: recentLogs.rows,
    topUsers: [],
    topBrands,
    institutional_users: parseInt(totals.rows[0].institutional_users || 0),
    external_users: parseInt(totals.rows[0].external_users || 0)
  };
}

module.exports = {
  getStats,
};
