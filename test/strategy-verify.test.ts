import 'mocha';
import { expect } from 'chai';
import * as sinon from 'sinon';
import { use } from './chai-passport-strategy';

import { JwtStrategy as Strategy } from '../src/strategy';
import * as testData from './testdata';
import { fromAuthHeaderAsBearerToken } from '../src/extract-jwt';
import { Request } from 'express';

describe('Strategy verify', () => {
  describe('Handling a request with a valid JWT and succesful verification', () => {
    before((done) => {
      const strategy = new Strategy(
        {
          extractToken: fromAuthHeaderAsBearerToken(),
          secretOrKey: 'secret',
          verifyJwt: async () => testData.payload,
        },
        (_paylod, next) => next(null, { user_id: 1234567890 }, { foo: 'bar' })
      );

      use(strategy, done)
        .success((user, info) => {
          expect(user).to.have.property('user_id', 1234567890);
          expect(info).to.have.property('foo', 'bar');
        })
        .req((req) => {
          req.headers['authorization'] = 'bearer ' + testData.token;
        })
        .authenticate();
    });

    it('should provide a user and info', () => {});
  });

  describe('handling a request with valid jwt and failed verification', () => {
    it('should fail with info', (done) => {
      const strategy = new Strategy(
        {
          extractToken: fromAuthHeaderAsBearerToken(),
          secretOrKey: 'secret',
          verifyJwt: async () => testData.payload,
        },
        (_payload, next) => next(null, false, { message: 'invalid user' })
      );

      use(strategy, done)
        .fail((info) => {
          expect(info).to.have.property('message', 'invalid user');
        })
        .req((req) => {
          req.headers['authorization'] = 'bearer ' + testData.token;
        })
        .authenticate();
    });
  });

  describe('handling a request with a valid jwt and an error during verification', () => {
    it('should error', (done) => {
      const strategy = new Strategy(
        {
          extractToken: fromAuthHeaderAsBearerToken(),
          secretOrKey: 'secret',
          verifyJwt: async () => testData.payload,
        },
        (_payload, next) =>
          next(new Error('ERROR'), false, { message: 'invalid user' })
      );

      use(strategy, done)
        .error((error) => {
          expect(error).to.be.an.instanceof(Error);
          expect(error.message).to.equal('ERROR');
        })
        .req((req) => {
          req.headers['authorization'] = 'bearer ' + testData.token;
        })
        .authenticate();
    });
  });

  describe('handling a request with a valid jwt and an exception during verification', () => {
    it('should error', (done) => {
      const strategy = new Strategy(
        {
          extractToken: fromAuthHeaderAsBearerToken(),
          secretOrKey: 'secret',
          verifyJwt: async () => testData.payload,
        },
        (_payload) => {
          throw new Error('EXCEPTION');
        }
      );

      use(strategy, done)
        .error((error) => {
          expect(error).to.be.an.instanceof(Error);
          expect(error.message).to.equal('EXCEPTION');
        })
        .req((req) => {
          req.headers['authorization'] = 'bearer ' + testData.token;
        })
        .authenticate();
    });
  });

  describe('handling a request with a valid jwt and option passReqToCallback is true', () => {
    it('will call verify with request as the first argument', (done) => {
      let expectedRequest: Request;
      let passedRequest: Request | undefined;

      const strategy = new Strategy(
        {
          passReqToCallback: true,
          verifyJwt: async () => testData.payload,
          secretOrKey: 'secret',
          extractToken: fromAuthHeaderAsBearerToken(),
        },
        ({ request }, next) => {
          passedRequest = request;
          return next(null, { user_id: 1234567890 }, { foo: 'bar' });
        }
      );

      use(strategy)
        .success(() => {
          try {
            expect(expectedRequest).to.equal(passedRequest);
            done();
          } catch (err) {
            done(err);
          }
        })
        .req((req) => {
          req.headers['authorization'] = 'bearer ' + testData.token;
          expectedRequest = req;
        })
        .authenticate();
    });
  });

  describe('handling a request when constructed with a secretOrKeyProvider function that succeeds', () => {
    it('should call the secret or key provider and jwt verifier', (done) => {
      let expectedRequest: Request;

      const verifyJwtStub = sinon.stub();
      verifyJwtStub.resolves(testData.payload);

      const fakeSecretOrKeyProvider = sinon.spy(
        async (_r, _t) => 'secret from callback'
      );

      const strategy = new Strategy(
        {
          secretOrKeyProvider: fakeSecretOrKeyProvider,
          extractToken: () => 'an undecoded jwt string',
          verifyJwt: verifyJwtStub,
        },
        (_payload, next) => next(null, { user_id: 'dont care' }, {})
      );

      use(strategy, done)
        .success(() => {
          expect(
            fakeSecretOrKeyProvider.calledWith(
              expectedRequest,
              'an undecoded jwt string'
            )
          ).to.be.true;
          expect(verifyJwtStub.args[0][0].secretOrKey).to.be.equal(
            'secret from callback'
          );
        })
        .req((req) => {
          expectedRequest = req;
        })
        .authenticate();
    });
  });

  describe('handling a request when constructed with a secretOrKeyProvider function that errors', () => {
    it('should fail with the error message from the secretOrKeyProvider', (done) => {
      const fakeSecretOrKeyProvider = sinon.spy(() => {
        throw 'Error occurred looking for the secret';
      });
      const strategy = new Strategy(
        {
          secretOrKeyProvider: fakeSecretOrKeyProvider,
          extractToken: () => 'an undecoded jwt string',
          verifyJwt: async () => testData.payload,
        },
        (_payload, next) => next(null, { user_id: 'dont care' }, {})
      );

      use(strategy, done)
        .fail((errorMessage) => {
          expect(errorMessage).to.equal(
            'Error occurred looking for the secret'
          );
        })
        .authenticate();
    });
  });
});
