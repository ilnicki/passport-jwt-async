const extractJwt = require('../lib/extract-jwt');

describe('Token extractor', () => {
  describe('fromHeader', () => {
    const extract = extractJwt.fromHeader('test_header');

    it('should return null no when token is present', () => {
      const req = {
        headers: {},
      };

      const token = extract(req);

      expect(token).to.be.null;
    });

    it('should return the value from the specified header', () => {
      const req = {
        headers: {
          test_header: 'abcd123',
        },
      };

      const token = extract(req);

      expect(token).to.equal('abcd123');
    });
  });

  describe('fromBodyField', () => {
    const extract = extractJwt.fromBodyField('test_field');

    it('should return null when no body is present', () => {
      const req = {};

      const token = extract(req);

      expect(token).to.be.null;
    });

    it('should return null when the specified body field is not present', () => {
      const req = {
        body: {},
      };

      const token = extract(req);

      expect(token).to.be.null;
    });

    it('should return the value from the specified body field', () => {
      const req = {
        body: {
          test_field: 'abcd123',
        },
      };

      const token = extract(req);

      expect(token).to.equal('abcd123');
    });

    it('should work properly with querystring', () => {
      const querystring = require('querystring');
      const body = querystring.parse('test_field=abcd123');
      const req = {
        body,
      };

      const token = extract(req);

      expect(token).to.equal('abcd123');
    });
  });

  describe('fromUrlQueryParameter', () => {
    const extractor = extractJwt.fromUrlQueryParameter('test_param');

    it('should return null when the specified paramter is not present', () => {
      const req = {
        url: '/',
      };

      const token = extractor(req);

      expect(token).to.be.null;
    });

    it('should return the value from the specified parameter', () => {
      const req = {
        url: '/?test_param=abcd123',
      };

      const token = extractor(req);

      expect(token).to.equal('abcd123');
    });
  });

  describe('fromAuthHeaderWithScheme', () => {
    const extract = extractJwt.fromAuthHeaderWithScheme('TEST_SCHEME');

    it('should return null when no auth header is present', () => {
      const req = {
        headers: {},
      };

      const token = extract(req);

      expect(token).to.be.null;
    });

    it('should return null when the auth header is present but the auth scheme doesnt match', () => {
      const req = {
        headers: {
          authorization: 'NOT_TEST_SCHEME abcd123',
        },
      };

      const token = extract(req);

      expect(token).to.be.null;
    });

    it('should return the value from the authorization header with specified auth scheme', () => {
      const req = {
        headers: {
          authorization: 'TEST_SCHEME abcd123',
        },
      };

      const token = extract(req);

      expect(token).to.equal('abcd123');
    });

    it('should perform a case-insensivite string comparison', () => {
      const req = {
        headers: {
          authorization: 'test_scheme abcd123',
        },
      };

      const token = extract(req);

      expect(token).to.equal('abcd123');
    });
  });

  describe('fromAuthHeader', () => {
    const extract = extractJwt.fromAuthHeaderAsBearerToken();

    it('should return the value from the authorization header with default JWT auth scheme', () => {
      const req = {
        headers: {
          authorization: 'bearer abcd123',
        },
      };

      const token = extract(req);

      expect(token).to.equal('abcd123');
    });
  });

  describe('fromExtractors', () => {
    it('should raise a type error when the extractor is constructed with a non-array argument', () => {
      const shouldThrow = () => {
        extractJwt.fromExtractors({});
      };

      expect(shouldThrow).to.throw(TypeError);
    });

    const extractor = extractJwt.fromExtractors([
      extractJwt.fromAuthHeaderAsBearerToken(),
      extractJwt.fromHeader('authorization'),
    ]);

    it('should return null when no extractor extracts token', () => {
      const req = {
        headers: {},
      };

      const token = extractor(req);

      expect(token).to.be.null;
    });

    it('should return token found by least extractor', () => {
      const req = {
        headers: { authorization: 'abcd123' },
      };

      const token = extractor(req);

      expect(token).to.equal('abcd123');
    });

    it('should return token found by first extractor', () => {
      const req = {
        headers: { authorization: 'bearer abcd123' },
      };

      const token = extractor(req);

      expect(token).to.equal('abcd123');
    });
  });
});
