const chai = require('chai');
const { JwtStrategy: Strategy } = require('../lib/strategy');
const testData = require('./testdata');
const sinon = require('sinon');
const extractJwt = require('../lib/extract-jwt');

describe('Strategy verify', () => {
  let verifyJwtStub;
  before(() => {
    verifyJwtStub = sinon.stub();
    verifyJwtStub.callsArgWith(3, null, testData.valid_jwt.payload);
  });

  describe('Handling a request with a valid JWT and succesful verification', () => {
    let strategy;
    let user;
    let info;

    before((done) => {
      strategy = new Strategy(
        {
          jwtFromRequest: extractJwt.fromAuthHeaderAsBearerToken(),
          secretOrKey: 'secret',
          verifyJwt: verifyJwtStub,
        },
        (jwt_paylod, next) =>
          next(null, { user_id: 1234567890 }, { foo: 'bar' })
      );

      chai.passport
        .use(strategy)
        .success((u, i) => {
          user = u;
          info = i;
          done();
        })
        .req((req) => {
          req.headers['authorization'] = 'bearer ' + testData.valid_jwt.token;
        })
        .authenticate();
    });

    it('should provide a user', () => {
      expect(user).to.be.an.object;
      expect(user.user_id).to.equal(1234567890);
    });

    it('should forward info', () => {
      expect(info).to.be.an.object;
      expect(info.foo).to.equal('bar');
    });
  });

  describe('handling a request with valid jwt and failed verification', () => {
    let strategy;
    let info;

    before((done) => {
      strategy = new Strategy(
        {
          jwtFromRequest: extractJwt.fromAuthHeaderAsBearerToken(),
          secretOrKey: 'secret',
          verifyJwt: verifyJwtStub,
        },
        (jwt_payload, next) => next(null, false, { message: 'invalid user' })
      );

      chai.passport
        .use(strategy)
        .fail((i) => {
          info = i;
          done();
        })
        .req((req) => {
          req.headers['authorization'] = 'bearer ' + testData.valid_jwt.token;
        })
        .authenticate();
    });

    it('should fail with info', () => {
      expect(info).to.be.an.object;
      expect(info.message).to.equal('invalid user');
    });
  });

  describe('handling a request with a valid jwt and an error during verification', () => {
    let strategy;
    let err;

    before((done) => {
      strategy = new Strategy(
        {
          jwtFromRequest: extractJwt.fromAuthHeaderAsBearerToken(),
          secretOrKey: 'secrety',
          verifyJwt: verifyJwtStub,
        },
        (jwt_payload, next) =>
          next(new Error('ERROR'), false, { message: 'invalid user' })
      );

      chai.passport
        .use(strategy)
        .error((e) => {
          err = e;
          done();
        })
        .req((req) => {
          req.headers['authorization'] = 'bearer ' + testData.valid_jwt.token;
        })
        .authenticate();
    });

    it('should error', () => {
      expect(err).to.be.an.instanceof(Error);
      expect(err.message).to.equal('ERROR');
    });
  });

  describe('handling a request with a valid jwt and an exception during verification', () => {
    let strategy;
    let err;

    before((done) => {
      strategy = new Strategy(
        {
          jwtFromRequest: extractJwt.fromAuthHeaderAsBearerToken(),
          secretOrKey: 'secret',
          verifyJwt: verifyJwtStub,
        },
        (jwt_payload, next) => {
          throw new Error('EXCEPTION');
        }
      );

      chai.passport
        .use(strategy)
        .error((e) => {
          err = e;
          done();
        })
        .req((req) => {
          req.headers['authorization'] = 'bearer ' + testData.valid_jwt.token;
        })
        .authenticate();
    });

    it('should error', () => {
      expect(err).to.be.an.instanceof(Error);
      expect(err.message).to.equal('EXCEPTION');
    });
  });

  describe('handling a request with a valid jwt and option passReqToCallback is true', () => {
    let strategy;
    let expected_request;
    let request_arg;

    before((done) => {
      strategy = new Strategy(
        {
          passReqToCallback: true,
          verifyJwt: verifyJwtStub,
          secretOrKey: 'secret',
          jwtFromRequest: extractJwt.fromAuthHeaderAsBearerToken(),
        },
        ({ request }, next) => {
          // Capture the value passed in as the request argument
          request_arg = request;
          return next(null, { user_id: 1234567890 }, { foo: 'bar' });
        }
      );

      chai.passport
        .use(strategy)
        .success(() => {
          done();
        })
        .req((req) => {
          req.headers['authorization'] = 'bearer ' + testData.valid_jwt.token;
          expected_request = req;
        })
        .authenticate();
    });

    it('will call verify with request as the first argument', () => {
      expect(expected_request).to.equal(request_arg);
    });
  });

  describe('handling a request when constructed with a secretOrKeyProvider function that succeeds', () => {
    let strategy;
    let fakeSecretOrKeyProvider;
    let expectedRequest;

    before((done) => {
      fakeSecretOrKeyProvider = sinon.spy(() => 'secret from callback');
      opts = {
        secretOrKeyProvider: fakeSecretOrKeyProvider,
        jwtFromRequest: () => 'an undecoded jwt string',
        verifyJwt: verifyJwtStub,
      };
      strategy = new Strategy(opts, (jwtPayload, next) =>
        next(null, { user_id: 'dont care' }, {})
      );

      chai.passport
        .use(strategy)
        .success(() => {
          done();
        })
        .req((req) => {
          expectedRequest = req;
        })
        .authenticate();
    });

    it('should call the fake secret or key provider with the reqeust', () => {
      expect(
        fakeSecretOrKeyProvider.calledWith(expectedRequest, sinon.match.any)
      ).to.be.true;
    });

    it('should call the secretOrKeyProvider with the undecoded jwt', () => {
      expect(
        fakeSecretOrKeyProvider.calledWith(
          sinon.match.any,
          'an undecoded jwt string'
        )
      ).to.be.true;
    });

    it('should call verifyJwt with the value returned from secretOrKeyProvider', () => {
      expect(
        verifyJwtStub.calledWith(
          sinon.match.any,
          'secret from callback',
          sinon.match.any,
          sinon.match.any
        )
      ).to.be.true;
    });
  });

  describe('handling a request when constructed with a secretOrKeyProvider function that errors', () => {
    let errorMessage;

    before((done) => {
      fakeSecretOrKeyProvider = sinon.spy(() => {
        throw 'Error occurred looking for the secret';
      });
      opts = {
        secretOrKeyProvider: fakeSecretOrKeyProvider,
        jwtFromRequest: (request) => 'an undecoded jwt string',
        verifyJwt: verifyJwtStub,
      };
      strategy = new Strategy(opts, (jwtPayload, next) =>
        next(null, { user_id: 'dont care' }, {})
      );

      chai.passport
        .use(strategy)
        .fail((i) => {
          errorMessage = i;
          done();
        })
        .authenticate();
    });

    it('should fail with the error message from the secretOrKeyProvider', () => {
      expect(errorMessage).to.equal('Error occurred looking for the secret');
    });
  });
});
