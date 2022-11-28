import { Request } from 'express';
import * as url from 'url';
import { parse } from './auth-header';

export type TokenExtractor = (request: Request) => string | null;

// Note: express http converts all headers to lower case.
const AUTH_HEADER = 'authorization';
const BEARER_AUTH_SCHEME = 'bearer';

export const fromHeader =
  (headerName: string): TokenExtractor =>
  (request) => {
    const header = request.headers[headerName];
    if (header && typeof header === 'string') {
      return header;
    }

    return null;
  };

export const fromBodyField =
  (fieldName: string): TokenExtractor =>
  (request) => {
    if (
      request.body &&
      Object.prototype.hasOwnProperty.call(request.body, fieldName)
    ) {
      return request.body[fieldName];
    }

    return null;
  };

export const fromUrlQueryParameter =
  (paramName: string): TokenExtractor =>
  (request) => {
    const {
      query: { [paramName]: param },
    } = url.parse(request.url, true);

    if (typeof param === 'string') {
      return param;
    }

    return null;
  };

export const fromAuthHeaderWithScheme = (
  authScheme: string
): TokenExtractor => {
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

export const fromExtractors = (
  extractors: TokenExtractor[]
): TokenExtractor => {
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
