'use strict';

const Strategy = require('./strategy');
const ExtractJwt = require('./extract-jwt');

module.exports = {
  Strategy: Strategy,
  ExtractJwt: ExtractJwt,
};
