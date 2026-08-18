'use strict';

const pool = require('./pool');
const config = require('./config');
const users = require('./users');
const devices = require('./devices');
const audit = require('./audit');
const admin = require('./admin');
const radiusDb = require('./radiusDb');
const reports = require('./reports');
const stats = require('./stats');
const hotelRestaurant = require('./hotelRestaurant');
const ldapDb = require('./ldapDb');
const macBypass = require('./macBypass');
const wpaUsers = require('./wpaUsers');

module.exports = {
  ...pool,
  ...config,
  ...users,
  ...devices,
  ...audit,
  ...admin,
  ...radiusDb,
  ...reports,
  ...stats,
  ...hotelRestaurant,
  ...ldapDb,
  ...macBypass,
  ...wpaUsers,
};
