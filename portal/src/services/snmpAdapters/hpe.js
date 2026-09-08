'use strict';

const generic = require('./generic');

async function poll(deviceConfig) {
  return generic.poll(deviceConfig);
}

module.exports = { poll };
