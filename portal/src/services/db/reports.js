'use strict';

const { getPool } = require('./pool');
const { getVendor } = require('mac-oui-lookup');

async function getUsersReport({ search = '', startDate, endDate, limit = 50, offset = 0 } = {}) {
  let query = `
    SELECT id, cedula, nombres, apellidos, email, activo, fecha_registro, acepta_terminos, fecha_acepta_terminos,
           (SELECT mac_address FROM dispositivos_usuario WHERE cedula = usuarios_portal.cedula LIMIT 1) AS mac_address
    FROM usuarios_portal
    WHERE 1=1
  `;
  const params = [];
  let paramIdx = 1;

  if (search) {
    query += ` AND (cedula ILIKE $${paramIdx} OR nombres ILIKE $${paramIdx} OR apellidos ILIKE $${paramIdx} OR email ILIKE $${paramIdx} OR EXISTS (SELECT 1 FROM dispositivos_usuario WHERE cedula = usuarios_portal.cedula AND mac_address ILIKE $${paramIdx}))`;
    params.push(`%${search}%`);
    paramIdx++;
  }

  if (startDate) {
    query += ` AND fecha_registro >= $${paramIdx}`;
    params.push(startDate);
    paramIdx++;
  }

  if (endDate) {
    query += ` AND fecha_registro <= $${paramIdx}`;
    params.push(endDate);
    paramIdx++;
  }

  // Get total count (Optimized count without columns subqueries)
  let countQuery = `SELECT COUNT(*) FROM usuarios_portal WHERE 1=1`;
  const countParams = [];
  let countParamIdx = 1;

  if (search) {
    countQuery += ` AND (cedula ILIKE $${countParamIdx} OR nombres ILIKE $${countParamIdx} OR apellidos ILIKE $${countParamIdx} OR email ILIKE $${countParamIdx} OR EXISTS (SELECT 1 FROM dispositivos_usuario WHERE cedula = usuarios_portal.cedula AND mac_address ILIKE $${countParamIdx}))`;
    countParams.push(`%${search}%`);
    countParamIdx++;
  }

  if (startDate) {
    countQuery += ` AND fecha_registro >= $${countParamIdx}`;
    countParams.push(startDate);
    countParamIdx++;
  }

  if (endDate) {
    countQuery += ` AND fecha_registro <= $${countParamIdx}`;
    countParams.push(endDate);
    countParamIdx++;
  }

  const totalRes = await getPool().query(countQuery, countParams);

  query += ` ORDER BY fecha_registro DESC LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`;
  params.push(limit, offset);

  const res = await getPool().query(query, params);

  return { data: res.rows, total: parseInt(totalRes.rows[0].count) };
}

async function getConnectionsReport({ search = '', ssid = '', startDate, endDate, limit = 50, offset = 0 } = {}) {
  let query = `
    SELECT r.radacctid, COALESCE(u.cedula, r.username) AS username, u.nombres, u.apellidos, r.callingstationid AS mac_address,
           r.framedipaddress AS ip_address, r.acctstarttime AS start_time, r.acctstoptime AS stop_time,
           CASE 
             WHEN POSITION(':' IN r.calledstationid) > 0 THEN SUBSTRING(r.calledstationid FROM POSITION(':' IN r.calledstationid) + 1)
             ELSE r.calledstationid
           END AS ssid,
           CASE 
             WHEN r.acctstoptime IS NULL THEN EXTRACT(EPOCH FROM (NOW() - r.acctstarttime))::bigint
             ELSE r.acctsessiontime
           END AS duration,
           r.acctinputoctets AS upload, r.acctoutputoctets AS download
    FROM radacct r
    LEFT JOIN dispositivos_usuario d ON REPLACE(UPPER(r.callingstationid), ':', '-') = REPLACE(UPPER(d.mac_address), ':', '-')
    LEFT JOIN usuarios_portal u ON u.cedula = (
      CASE 
        WHEN r.username ~ '^[0-9]+$' THEN r.username 
        ELSE d.cedula 
      END
    )
    WHERE 1=1
  `;
  const params = [];
  let paramIdx = 1;

  if (search) {
    query += ` AND (r.username ILIKE $${paramIdx} OR u.cedula ILIKE $${paramIdx} OR u.nombres ILIKE $${paramIdx} OR u.apellidos ILIKE $${paramIdx} OR r.callingstationid ILIKE $${paramIdx} OR CAST(r.framedipaddress AS TEXT) ILIKE $${paramIdx})`;
    params.push(`%${search}%`);
    paramIdx++;
  }

  if (ssid) {
    query += ` AND (r.calledstationid ILIKE $${paramIdx} OR (POSITION(':' IN r.calledstationid) > 0 AND SUBSTRING(r.calledstationid FROM POSITION(':' IN r.calledstationid) + 1) ILIKE $${paramIdx}))`;
    params.push(`%${ssid}%`);
    paramIdx++;
  }

  if (startDate) {
    query += ` AND r.acctstarttime >= $${paramIdx}`;
    params.push(startDate);
    paramIdx++;
  }

  if (endDate) {
    query += ` AND r.acctstarttime <= $${paramIdx}`;
    params.push(endDate);
    paramIdx++;
  }

  // Get total count (Optimized count query without joins if no user search is present)
  let countQuery;
  const countParams = [];
  let countParamIdx = 1;

  if (search) {
    countQuery = `
      SELECT COUNT(*)
      FROM radacct r
      LEFT JOIN dispositivos_usuario d ON REPLACE(UPPER(r.callingstationid), ':', '-') = REPLACE(UPPER(d.mac_address), ':', '-')
      LEFT JOIN usuarios_portal u ON u.cedula = (
        CASE 
          WHEN r.username ~ '^[0-9]+$' THEN r.username 
          ELSE d.cedula 
        END
      )
      WHERE 1=1
      AND (r.username ILIKE $${countParamIdx} OR u.cedula ILIKE $${countParamIdx} OR u.nombres ILIKE $${countParamIdx} OR u.apellidos ILIKE $${countParamIdx} OR r.callingstationid ILIKE $${countParamIdx} OR CAST(r.framedipaddress AS TEXT) ILIKE $${countParamIdx})
    `;
    countParams.push(`%${search}%`);
    countParamIdx++;
  } else {
    countQuery = `SELECT COUNT(*) FROM radacct r WHERE 1=1`;
  }

  if (ssid) {
    countQuery += ` AND (r.calledstationid ILIKE $${countParamIdx} OR (POSITION(':' IN r.calledstationid) > 0 AND SUBSTRING(r.calledstationid FROM POSITION(':' IN r.calledstationid) + 1) ILIKE $${countParamIdx}))`;
    countParams.push(`%${ssid}%`);
    countParamIdx++;
  }

  if (startDate) {
    countQuery += ` AND r.acctstarttime >= $${countParamIdx}`;
    countParams.push(startDate);
    countParamIdx++;
  }

  if (endDate) {
    countQuery += ` AND r.acctstarttime <= $${countParamIdx}`;
    countParams.push(endDate);
    countParamIdx++;
  }

  const totalRes = await getPool().query(countQuery, countParams);

  query += ` ORDER BY r.acctstarttime DESC LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`;
  params.push(limit, offset);

  const res = await getPool().query(query, params);

  return { data: res.rows, total: parseInt(totalRes.rows[0].count) };
}

async function getConsolidatedConnectionsReport({ search = '', ssid = '', startDate, endDate, limit = 50, offset = 0 } = {}) {
  let innerQuery = `
    SELECT 
      COALESCE(u.cedula, r.username) AS cedula,
      COALESCE(u.nombres, 'Sin Registro') AS nombres,
      COALESCE(u.apellidos, '') AS apellidos,
      u.tipo_usuario,
      REPLACE(UPPER(r.callingstationid), ':', '-') AS mac_address,
      MAX(
        CASE 
          WHEN POSITION(':' IN r.calledstationid) > 0 THEN SUBSTRING(r.calledstationid FROM POSITION(':' IN r.calledstationid) + 1)
          ELSE r.calledstationid
        END
      ) AS ssid,
      COUNT(r.radacctid)::int AS total_sesiones,
      MIN(r.acctstarttime) AS primera_conexion,
      MAX(r.acctstarttime) AS ultima_conexion,
      SUM(
        CASE 
          WHEN r.acctstoptime IS NULL THEN EXTRACT(EPOCH FROM (NOW() - r.acctstarttime))::bigint
          ELSE r.acctsessiontime
        END
      )::bigint AS duration,
      SUM(COALESCE(r.acctinputoctets, 0))::bigint AS upload,
      SUM(COALESCE(r.acctoutputoctets, 0))::bigint AS download,
      SUM(COALESCE(r.acctinputoctets, 0) + COALESCE(r.acctoutputoctets, 0))::bigint AS total_bytes
    FROM radacct r
    LEFT JOIN dispositivos_usuario d ON REPLACE(UPPER(r.callingstationid), ':', '-') = REPLACE(UPPER(d.mac_address), ':', '-')
    LEFT JOIN usuarios_portal u ON u.cedula = (
      CASE 
        WHEN r.username ~ '^[0-9]+$' THEN r.username 
        ELSE d.cedula 
      END
    )
    WHERE r.callingstationid IS NOT NULL AND r.callingstationid <> ''
  `;
  const params = [];
  let paramIdx = 1;

  if (search) {
    innerQuery += ` AND (r.username ILIKE $${paramIdx} OR u.cedula ILIKE $${paramIdx} OR u.nombres ILIKE $${paramIdx} OR u.apellidos ILIKE $${paramIdx} OR r.callingstationid ILIKE $${paramIdx})`;
    params.push(`%${search}%`);
    paramIdx++;
  }

  if (ssid) {
    innerQuery += ` AND (r.calledstationid ILIKE $${paramIdx} OR (POSITION(':' IN r.calledstationid) > 0 AND SUBSTRING(r.calledstationid FROM POSITION(':' IN r.calledstationid) + 1) ILIKE $${paramIdx}))`;
    params.push(`%${ssid}%`);
    paramIdx++;
  }

  if (startDate) {
    innerQuery += ` AND r.acctstarttime >= $${paramIdx}`;
    params.push(startDate);
    paramIdx++;
  }

  if (endDate) {
    innerQuery += ` AND r.acctstarttime <= $${paramIdx}`;
    params.push(endDate);
    paramIdx++;
  }

  innerQuery += ` GROUP BY COALESCE(u.cedula, r.username), u.nombres, u.apellidos, u.tipo_usuario, REPLACE(UPPER(r.callingstationid), ':', '-')`;

  const countQuery = `SELECT COUNT(*) FROM (${innerQuery}) AS total_cnt`;
  const totalRes = await getPool().query(countQuery, params);

  let fullQuery = `${innerQuery} ORDER BY total_bytes DESC LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`;
  params.push(limit, offset);

  const res = await getPool().query(fullQuery, params);
  const data = res.rows.map(row => ({
    ...row,
    vendor: getVendor(row.mac_address)
  }));

  return { data, total: parseInt(totalRes.rows[0].count) };
}

async function getDistinctSsids() {
  const res = await getPool().query(`
    SELECT DISTINCT 
      CASE 
        WHEN POSITION(':' IN calledstationid) > 0 THEN SUBSTRING(calledstationid FROM POSITION(':' IN calledstationid) + 1)
        ELSE calledstationid
      END AS ssid
    FROM radacct 
    WHERE calledstationid IS NOT NULL AND calledstationid <> ''
    ORDER BY ssid ASC
  `);
  return res.rows.map(r => r.ssid).filter(Boolean);
}

async function getAccessLogReport({ search = '', startDate, endDate, limit = 50, offset = 0 } = {}) {
  let query = `
    SELECT a.id, a.cedula, u.nombres, u.apellidos, a.vendor, a.mac_address, a.ip_address, a.resultado, a.created_at
    FROM access_log a
    LEFT JOIN usuarios_portal u ON a.cedula = u.cedula
    WHERE 1=1
  `;
  const params = [];
  let paramIdx = 1;

  if (search) {
    query += ` AND (a.cedula ILIKE $${paramIdx} OR u.nombres ILIKE $${paramIdx} OR u.apellidos ILIKE $${paramIdx} OR a.mac_address ILIKE $${paramIdx} OR CAST(a.ip_address AS TEXT) ILIKE $${paramIdx})`;
    params.push(`%${search}%`);
    paramIdx++;
  }

  if (startDate) {
    query += ` AND a.created_at >= $${paramIdx}`;
    params.push(startDate);
    paramIdx++;
  }

  if (endDate) {
    query += ` AND a.created_at <= $${paramIdx}`;
    params.push(endDate);
    paramIdx++;
  }

  // Get total count
  const countQuery = `SELECT COUNT(*) FROM (${query}) AS total`;
  const totalRes = await getPool().query(countQuery, params);

  query += ` ORDER BY a.created_at DESC LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`;
  params.push(limit, offset);

  const res = await getPool().query(query, params);

  return { data: res.rows, total: parseInt(totalRes.rows[0].count) };
}

module.exports = {
  getUsersReport,
  getConnectionsReport,
  getConsolidatedConnectionsReport,
  getDistinctSsids,
  getAccessLogReport,
};
