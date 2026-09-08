'use strict';

const generic = require('./generic');
const { OIDS, buildSession, getTarget, walkTarget, closeSession } = require('../snmpClient');

async function poll(deviceConfig) {
  const result = await generic.poll(deviceConfig);
  return result;
}

module.exports = { poll };
