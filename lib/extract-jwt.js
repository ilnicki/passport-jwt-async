'use strict';

const url = require('url');
const { parse } = require('./auth-header');

// Note: express http converts all headers
// to lower case.
const AUTH_HEADER = 'authorization';
const BEARER_AUTH_SCHEME = 'bearer';

const extractors = {};

extractors.fromHeader = function (header_name) {
  return function (request) {
    if (request.headers[header_name]) {
      return request.headers[header_name];
    }

    return null;
  };
};

extractors.fromBodyField = function (field_name) {
  return function (request) {
    if (
      request.body &&
      Object.prototype.hasOwnProperty.call(request.body, field_name)
    ) {
      return request.body[field_name];
    }

    return null;
  };
};

extractors.fromUrlQueryParameter = function (param_name) {
  return function (request) {
    const parsedUrl = url.parse(request.url, true);

    if (
      parsedUrl.query &&
      Object.prototype.hasOwnProperty.call(parsedUrl.query, param_name)
    ) {
      return parsedUrl.query[param_name];
    }

    return null;
  };
};

extractors.fromAuthHeaderWithScheme = function (authScheme) {
  const authSchemeLower = authScheme.toLowerCase();
  return function (request) {
    if (request.headers[AUTH_HEADER]) {
      const authParams = parse(request.headers[AUTH_HEADER]);
      if (authParams && authSchemeLower === authParams.scheme.toLowerCase()) {
        return authParams.value;
      }
    }

    return null;
  };
};

extractors.fromAuthHeaderAsBearerToken = function () {
  return extractors.fromAuthHeaderWithScheme(BEARER_AUTH_SCHEME);
};

extractors.fromExtractors = function (extractors) {
  if (!Array.isArray(extractors)) {
    throw new TypeError('extractors.fromExtractors expects an array');
  }

  return function (request) {
    let token = null;
    extractors.some((extract) => {
      return (token = extract.call(this, request));
    });
    return token;
  };
};

/**
 * Export the Jwt extraction functions
 */
module.exports = extractors;
