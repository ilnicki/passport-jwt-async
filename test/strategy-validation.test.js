const { JwtStrategy: Strategy } = require('../lib/strategy');
const chai = require('chai');
const test_data = require('./testdata');
const sinon = require('sinon');
const extractJwt = require('../lib/extract-jwt');

describe('Strategy validation', () => {
  describe('calling JWT validation function', () => {
    let strategy;
    let verifyJwtStub;

    before((done) => {
      const verifyStub = sinon.stub();
      verifyStub.callsArgWith(1, null, {}, {});

      verifyJwtStub = sinon.stub();
      verifyJwtStub.callsArgWith(3, null, test_data.valid_jwt.payload);

      const options = {
        secretOrKey: 'secret',
        verifyJwt: verifyJwtStub,
        verifyJwtOptions: {
          algorithms: ['HS256', 'HS384'],
          issuer: 'TestIssuer',
          audience: 'TestAudience',
          clockTolerance: 10,
          maxAge: '1h',
          ignoreExpiration: false,
        },
        jwtFromRequest: extractJwt.fromAuthHeaderAsBearerToken(),
      };

      strategy = new Strategy(options, verifyStub);

      chai.passport
        .use(strategy)
        .success(() => {
          done();
        })
        .req((req) => {
          req.headers['authorization'] = 'bearer ' + test_data.valid_jwt.token;
        })
        .authenticate();
    });

    it('should call with the right secret as an argument', () => {
      expect(verifyJwtStub.args[0][1]).to.equal('secret');
    });

    it('should call with the right issuer option', () => {
      expect(verifyJwtStub.args[0][2]).to.be.an.object;
      expect(verifyJwtStub.args[0][2].issuer).to.equal('TestIssuer');
    });

    it('should call with the right audience option', () => {
      expect(verifyJwtStub.args[0][2]).to.be.an.object;
      expect(verifyJwtStub.args[0][2].audience).to.equal('TestAudience');
    });

    it('should call with the right algorithms option', () => {
      expect(verifyJwtStub.args[0][2]).to.be.an.object;
      expect(verifyJwtStub.args[0][2].algorithms).to.eql(['HS256', 'HS384']);
    });

    it('should call with the right ignoreExpiration option', () => {
      expect(verifyJwtStub.args[0][2]).to.be.an.object;
      expect(verifyJwtStub.args[0][2].ignoreExpiration).to.be.false;
    });

    it('should call with the right maxAge option', () => {
      expect(verifyJwtStub.args[0][2]).to.be.an.object;
      expect(verifyJwtStub.args[0][2].maxAge).to.equal('1h');
    });

    it('should call with the right clockTolerance option', () => {
      expect(verifyJwtStub.args[0][2]).to.be.an.object;
      expect(verifyJwtStub.args[0][2].clockTolerance).to.equal(10);
    });
  });

  describe('handling valid jwt', () => {
    let strategy;
    let payload;

    before((done) => {
      const verifyJwtStub = sinon.stub();
      strategy = new Strategy(
        {
          jwtFromRequest: extractJwt.fromAuthHeaderAsBearerToken(),
          secretOrKey: 'secret',
          verifyJwt: verifyJwtStub,
        },
        ({ payload: jwtPayload }, next) => {
          payload = jwtPayload;
          next(null, {}, {});
        }
      );

      verifyJwtStub.callsArgWith(3, null, test_data.valid_jwt.payload);

      chai.passport
        .use(strategy)
        .success(() => {
          done();
        })
        .req((req) => {
          req.headers['authorization'] = 'bearer ' + test_data.valid_jwt.token;
        })
        .authenticate();
    });

    it('should call verify with the correct payload', () => {
      expect(payload).to.deep.equal(test_data.valid_jwt.payload);
    });
  });

  describe('handling failing jwt', () => {
    let strategy;
    let info;
    let verify_spy = sinon.spy();

    before((done) => {
      const verifyJwtStub = sinon.stub();
      strategy = new Strategy(
        {
          jwtFromRequest: extractJwt.fromAuthHeaderAsBearerToken(),
          secretOrKey: 'secret',
          verifyJwt: verifyJwtStub,
        },
        verify_spy
      );

      verifyJwtStub.callsArgWith(3, new Error('jwt expired'), false);

      chai.passport
        .use(strategy)
        .fail((i) => {
          info = i;
          done();
        })
        .req((req) => {
          req.headers['authorization'] = 'bearer ' + test_data.valid_jwt.token;
        })
        .authenticate();
    });

    it('should not call verify', () => {
      sinon.assert.notCalled(verify_spy);
    });

    it('should fail with error message.', () => {
      expect(info).to.be.an.object;
      expect(info.message).to.equal('jwt expired');
    });
  });

  describe('handling an invalid authentication header', () => {
    let strategy;
    let info;
    let verify_spy = sinon.spy();

    before((done) => {
      strategy = new Strategy(
        {
          jwtFromRequest: extractJwt.fromAuthHeaderAsBearerToken(),
          secretOrKey: 'secret',
        },
        verify_spy
      );

      chai.passport
        .use(strategy)
        .fail((i) => {
          info = i;
          done();
        })
        .req((req) => {
          req.headers['authorization'] = 'malformed';
        })
        .authenticate();
    });

    it('should not call verify', () => {
      sinon.assert.notCalled(verify_spy);
    });

    it('should fail with error message.', () => {
      expect(info).to.be.an.object;
      expect(info).to.be.an.instanceof(Error);
    });
  });
});
