'use strict';

const generic = require('./generic');

const CISCO_VLANS = '1.3.6.1.4.1.9.9.46.1.3.1.1.2';

async function poll(deviceConfig) {
  const { buildSession, walkTarget, closeSession } = require('../snmpClient');
  const result = await generic.poll(deviceConfig);

  try {
    const session = buildSession(deviceConfig);
    const vlanEntries = await walkTarget(session, CISCO_VLANS);
    result.vlans = vlanEntries.map(v => ({
      vlanId: parseInt(v.oid.split('.').pop()),
      name: String(v.value),
    }));
    closeSession(session);
  } catch (err) {
    result.errors.push(`cisco_vlans: ${err.message}`);
  }

  return result;
}

module.exports = { poll };
