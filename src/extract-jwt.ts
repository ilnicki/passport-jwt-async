import * as url from 'url';
import { parse } from './auth-header';

// Note: express http converts all headers to lower case.
const AUTH_HEADER = 'authorization';
const BEARER_AUTH_SCHEME = 'bearer';

export const fromHeader = (header_name) => (request) => {
  if (request.headers[header_name]) {
    return request.headers[header_name];
  }

  return null;
};

export const fromBodyField = (field_name) => (request) => {
  if (
    request.body &&
    Object.prototype.hasOwnProperty.call(request.body, field_name)
  ) {
    return request.body[field_name];
  }

  return null;
};

export const fromUrlQueryParameter = (param_name) => (request) => {
  const parsedUrl = url.parse(request.url, true);

  if (
    parsedUrl.query &&
    Object.prototype.hasOwnProperty.call(parsedUrl.query, param_name)
  ) {
    return parsedUrl.query[param_name];
  }

  return null;
};

export const fromAuthHeaderWithScheme = (authScheme) => {
  const authSchemeLower = authScheme.toLowerCase();
  return (request) => {
    if (request.headers[AUTH_HEADER]) {
      const authParams = parse(request.headers[AUTH_HEADER]);
      if (authParams && authSchemeLower === authParams.scheme.toLowerCase()) {
        return authParams.value;
      }
    }

    return null;
  };
};

export const fromAuthHeaderAsBearerToken = () =>
  fromAuthHeaderWithScheme(BEARER_AUTH_SCHEME);

export const fromExtractors = (extractors) => {
  if (!Array.isArray(extractors)) {
    throw new TypeError('extractors.fromExtractors expects an array');
  }

  return (request) => {
    let token = null;
    extractors.some((extract) => {
      return (token = extract(request));
    });
    return token;
  };
};
