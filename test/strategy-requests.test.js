const { JwtStrategy: Strategy } = require('../lib/strategy');
const chai = require('chai');
const sinon = require('sinon');
const testData = require('./testdata');
const url = require('url');

describe('Strategy requests', () => {
  let verifyJwtMock = null;

  before(() => {
    verifyJwtMock = sinon.stub();
    verifyJwtMock.callsArgWith(3, null, testData.valid_jwt.payload);
  });

  describe('handling request JWT present in request', () => {
    let strategy;

    before((done) => {
      strategy = new Strategy(
        {
          jwtFromRequest: () => testData.valid_jwt.token,
          secretOrKey: 'secret',
          verifyJwt: verifyJwtMock,
        },
        (jwt_payload, next) =>
          // Return values aren't important in this case
          next(null, {}, {})
      );

      verifyJwtMock.reset();

      chai.passport
        .use(strategy)
        .success(() => {
          done();
        })
        .authenticate();
    });

    it('verifies the right jwt', () => {
      sinon.assert.calledOnce(verifyJwtMock);
      expect(verifyJwtMock.args[0][0]).to.equal(testData.valid_jwt.token);
    });
  });

  describe('handling request with NO JWT', () => {
    let info;

    before((done) => {
      strategy = new Strategy(
        {
          jwtFromRequest: () => {},
          secretOrKey: 'secret',
          verifyJwt: verifyJwtMock,
        },
        (jwt_payload, next) =>
          // Return values aren't important in this case
          next(null, {}, {})
      );

      verifyJwtMock.reset();

      chai.passport
        .use(strategy)
        .fail((i) => {
          info = i;
          done();
        })
        .req((req) => {
          req.body = {};
        })
        .authenticate();
    });

    it('should fail authentication', () => {
      expect(info).to.be.an.object;
      expect(info.message).to.equal('No auth token');
    });

    it('Should not try to verify anything', () => {
      sinon.assert.notCalled(verifyJwtMock);
    });
  });

  describe('handling request url set to url.Url instead of string', () => {
    let info;

    before((done) => {
      strategy = new Strategy(
        {
          jwtFromRequest: () => {},
          secretOrKey: 'secret',
          verifyJwt: verifyJwtMock,
        },
        (jwt_payload, next) =>
          // Return values aren't important in this case
          next(null, {}, {})
      );

      verifyJwtMock.reset();

      chai.passport
        .use(strategy)
        .fail((i) => {
          info = i;
          done();
        })
        .req((req) => {
          req.body = {};
          req.url = new url.Url('/');
        })
        .authenticate();
    });

    it('should fail authentication', () => {
      expect(info).to.be.an.object;
      expect(info.message).to.equal('No auth token');
    });
  });
});