const extractJwt = require('../lib/extract-jwt');
const Request = require('./mock-request');

describe('Token extractor', function () {
  describe('fromHeader', function () {
    const extractor = extractJwt.fromHeader('test_header');

    it('should return null no when token is present', function () {
      const req = new Request();

      const token = extractor(req);

      expect(token).to.be.null;
    });

    it('should return the value from the specified header', function () {
      const req = new Request();
      req.headers['test_header'] = 'abcd123';

      const token = extractor(req);

      expect(token).to.equal('abcd123');
    });
  });

  describe('fromBodyField', function () {
    const extractor = extractJwt.fromBodyField('test_field');

    it('should return null when no body is present', function () {
      const req = new Request();

      const token = extractor(req);

      expect(token).to.be.null;
    });

    it('should return null when the specified body field is not present', function () {
      const req = new Request();
      req.body = {};

      const token = extractor(req);

      expect(token).to.be.null;
    });

    it('should return the value from the specified body field', function () {
      const req = new Request();
      req.body = {};
      req.body.test_field = 'abcd123';

      const token = extractor(req);

      expect(token).to.equal('abcd123');
    });

    it('should work properly with querystring', function () {
      const req = new Request();
      const querystring = require('querystring');
      req.body = querystring.parse('test_field=abcd123');

      const token = extractor(req);

      expect(token).to.equal('abcd123');
    });
  });

  describe('fromUrlQueryParameter', function () {
    const extractor = extractJwt.fromUrlQueryParameter('test_param');

    it('should return null when the specified paramter is not present', function () {
      const req = new Request();

      const token = extractor(req);

      expect(token).to.be.null;
    });

    it('should return the value from the specified parameter', function () {
      const req = new Request();
      req.url += '?test_param=abcd123';

      const token = extractor(req);

      expect(token).to.equal('abcd123');
    });
  });

  describe('fromAuthHeaderWithScheme', function () {
    const extractor = extractJwt.fromAuthHeaderWithScheme('TEST_SCHEME');

    it('should return null when no auth header is present', function () {
      const req = new Request();

      const token = extractor(req);

      expect(token).to.be.null;
    });

    it('should return null when the auth header is present but the auth scheme doesnt match', function () {
      const req = new Request();
      req.headers['authorization'] = 'NOT_TEST_SCHEME abcd123';

      const token = extractor(req);

      expect(token).to.be.null;
    });

    it('should return the value from the authorization header with specified auth scheme', function () {
      const req = new Request();
      req.headers['authorization'] = 'TEST_SCHEME abcd123';

      const token = extractor(req);

      expect(token).to.equal('abcd123');
    });

    it('should perform a case-insensivite string comparison', function () {
      const req = new Request();
      req.headers['authorization'] = 'test_scheme abcd123';

      const token = extractor(req);

      expect(token).to.equal('abcd123');
    });
  });

  describe('fromAuthHeader', function () {
    const extractor = extractJwt.fromAuthHeaderAsBearerToken();

    it('should return the value from the authorization header with default JWT auth scheme', function () {
      const req = new Request();
      req.headers['authorization'] = 'bearer abcd123';

      const token = extractor(req);

      expect(token).to.equal('abcd123');
    });
  });

  describe('fromExtractors', function () {
    it('should raise a type error when the extractor is constructed with a non-array argument', function () {
      this_should_throw = function () {
        const extractor = extractJwt.fromExtractors({});
      };

      expect(this_should_throw).to.throw(TypeError);
    });

    const extractor = extractJwt.fromExtractors([
      extractJwt.fromAuthHeaderAsBearerToken(),
      extractJwt.fromHeader('authorization'),
    ]);

    it('should return null when no extractor extracts token', function () {
      const req = new Request();

      const token = extractor(req);

      expect(token).to.be.null;
    });

    it('should return token found by least extractor', function () {
      const req = new Request();
      req.headers['authorization'] = 'abcd123';

      const token = extractor(req);

      expect(token).to.equal('abcd123');
    });

    it('should return token found by first extractor', function () {
      const req = new Request();
      req.headers['authorization'] = 'bearer abcd123';

      const token = extractor(req);

      expect(token).to.equal('abcd123');
    });
  });
});
