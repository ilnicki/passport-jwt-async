const Strategy = require('../lib/strategy');
const chai = require('chai');
const sinon = require('sinon');
const testData = require('./testdata');
const url = require('url');

describe('Strategy', function () {
  let mockVerifier = null;

  before(function () {
    // Replace the JWT Verfier with a stub to capture the value
    // extracted from the request
    mockVerifier = sinon.stub();
    mockVerifier.callsArgWith(3, null, testData.valid_jwt.payload);
    Strategy.JwtVerifier = mockVerifier;
  });

  describe('handling request JWT present in request', function () {
    let strategy;

    before(function (done) {
      strategy = new Strategy(
        {
          jwtFromRequest: function (r) {
            return testData.valid_jwt.token;
          },
          secretOrKey: 'secret',
        },
        function (jwt_payload, next) {
          // Return values aren't important in this case
          return next(null, {}, {});
        }
      );

      mockVerifier.reset();

      chai.passport
        .use(strategy)
        .success(function (u, i) {
          done();
        })
        .authenticate();
    });

    it('verifies the right jwt', function () {
      sinon.assert.calledOnce(mockVerifier);
      expect(mockVerifier.args[0][0]).to.equal(testData.valid_jwt.token);
    });
  });

  describe('handling request with NO JWT', function () {
    let info;

    before(function (done) {
      strategy = new Strategy(
        { jwtFromRequest: function (r) {}, secretOrKey: 'secret' },
        function (jwt_payload, next) {
          // Return values aren't important in this case
          return next(null, {}, {});
        }
      );

      mockVerifier.reset();

      chai.passport
        .use(strategy)
        .fail(function (i) {
          info = i;
          done();
        })
        .req(function (req) {
          req.body = {};
        })
        .authenticate();
    });

    it('should fail authentication', function () {
      expect(info).to.be.an.object;
      expect(info.message).to.equal('No auth token');
    });

    it('Should not try to verify anything', function () {
      sinon.assert.notCalled(mockVerifier);
    });
  });

  describe('handling request url set to url.Url instead of string', function () {
    let info;

    before(function (done) {
      strategy = new Strategy(
        { jwtFromRequest: function (r) {}, secretOrKey: 'secret' },
        function (jwt_payload, next) {
          // Return values aren't important in this case
          return next(null, {}, {});
        }
      );

      mockVerifier.reset();

      chai.passport
        .use(strategy)
        .fail(function (i) {
          info = i;
          done();
        })
        .req(function (req) {
          req.body = {};
          req.url = new url.Url('/');
        })
        .authenticate();
    });

    it('should fail authentication', function () {
      expect(info).to.be.an.object;
      expect(info.message).to.equal('No auth token');
    });
  });
});
