import 'mocha';
import { expect } from 'chai';
import { Request } from 'express';

import {
  fromAuthHeaderAsBearerToken,
  fromAuthHeaderWithScheme,
  fromBodyField,
  fromExtractors,
  fromHeader,
  fromUrlQueryParameter,
} from '../src/extract-jwt';

const requestWith = (overrides: Partial<Request>): Request =>
  ({
    ...overrides,
  } as unknown as Request);

describe('Token extractor', () => {
  describe('fromHeader', () => {
    const extract = fromHeader('test_header');

    it('should return null no when token is present', () => {
      const request = requestWith({
        headers: {},
      });

      const token = extract(request);

      expect(token).to.be.null;
    });

    it('should return the value from the specified header', () => {
      const request = requestWith({
        headers: {
          test_header: 'abcd123',
        },
      });

      const token = extract(request);

      expect(token).to.equal('abcd123');
    });
  });

  describe('fromBodyField', () => {
    const extract = fromBodyField('test_field');

    it('should return null when no body is present', () => {
      const request = requestWith({});

      const token = extract(request);

      expect(token).to.be.null;
    });

    it('should return null when the specified body field is not present', () => {
      const request = requestWith({
        body: {},
      });

      const token = extract(request);

      expect(token).to.be.null;
    });

    it('should return the value from the specified body field', () => {
      const request = requestWith({
        body: {
          test_field: 'abcd123',
        },
      });

      const token = extract(request);

      expect(token).to.equal('abcd123');
    });

    it('should work properly with querystring', () => {
      const querystring = require('querystring');
      const body = querystring.parse('test_field=abcd123');
      const request = requestWith({
        body,
      });

      const token = extract(request);

      expect(token).to.equal('abcd123');
    });
  });

  describe('fromUrlQueryParameter', () => {
    const extractor = fromUrlQueryParameter('test_param');

    it('should return null when the specified paramter is not present', () => {
      const request = requestWith({
        url: '/',
      });

      const token = extractor(request);

      expect(token).to.be.null;
    });

    it('should return the value from the specified parameter', () => {
      const request = requestWith({
        url: '/?test_param=abcd123',
      });

      const token = extractor(request);

      expect(token).to.equal('abcd123');
    });
  });

  describe('fromAuthHeaderWithScheme', () => {
    const extract = fromAuthHeaderWithScheme('TEST_SCHEME');

    it('should return null when no auth header is present', () => {
      const request = requestWith({
        headers: {},
      });

      const token = extract(request);

      expect(token).to.be.null;
    });

    it('should return null when the auth header is present but the auth scheme doesnt match', () => {
      const request = requestWith({
        headers: {
          authorization: 'NOT_TEST_SCHEME abcd123',
        },
      });

      const token = extract(request);

      expect(token).to.be.null;
    });

    it('should return the value from the authorization header with specified auth scheme', () => {
      const request = requestWith({
        headers: {
          authorization: 'TEST_SCHEME abcd123',
        },
      });

      const token = extract(request);

      expect(token).to.equal('abcd123');
    });

    it('should perform a case-insensivite string comparison', () => {
      const request = requestWith({
        headers: {
          authorization: 'test_scheme abcd123',
        },
      });

      const token = extract(request);

      expect(token).to.equal('abcd123');
    });
  });

  describe('fromAuthHeader', () => {
    const extract = fromAuthHeaderAsBearerToken();

    it('should return the value from the authorization header with default JWT auth scheme', () => {
      const request = requestWith({
        headers: {
          authorization: 'bearer abcd123',
        },
      });

      const token = extract(request);

      expect(token).to.equal('abcd123');
    });
  });

  describe('fromExtractors', () => {
    it('should raise a type error when the extractor is constructed with a non-array argument', () => {
      const shouldThrow = () => {
        fromExtractors({} as []);
      };

      expect(shouldThrow).to.throw(TypeError);
    });

    const extractor = fromExtractors([
      fromAuthHeaderAsBearerToken(),
      fromHeader('authorization'),
    ]);

    it('should return null when no extractor extracts token', () => {
      const request = requestWith({
        headers: {},
      });

      const token = extractor(request);

      expect(token).to.be.null;
    });

    it('should return token found by least extractor', () => {
      const request = requestWith({
        headers: { authorization: 'abcd123' },
      });

      const token = extractor(request);

      expect(token).to.equal('abcd123');
    });

    it('should return token found by first extractor', () => {
      const request = requestWith({
        headers: { authorization: 'bearer abcd123' },
      });

      const token = extractor(request);

      expect(token).to.equal('abcd123');
    });
  });
});
