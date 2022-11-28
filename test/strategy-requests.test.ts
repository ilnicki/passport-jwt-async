import 'mocha';
import { expect } from 'chai';
import * as sinon from 'sinon';
import { URL } from 'url';
import { use } from './chai-passport-strategy';

import { JwtStrategy as Strategy } from '../src/strategy';
import * as testData from './testdata';

describe('Strategy requests', () => {
  describe('handling request JWT present in request', () => {
    it('verifies the right jwt', (done) => {
      const verifyJwtMock = sinon.stub();
      verifyJwtMock.resolves(testData.payload);

      const strategy = new Strategy(
        {
          extractToken: () => testData.token,
          secretOrKey: 'secret',
          verifyJwt: verifyJwtMock,
        },
        (_payload, next) =>
          // Return values aren't important in this case
          next(null, {}, {})
      );

      use(strategy, done)
        .success(() => {
          sinon.assert.calledOnce(verifyJwtMock);
          expect(verifyJwtMock.args[0][0].token).to.equal(testData.token);
        })
        .authenticate();
    });
  });

  describe('handling request with NO JWT', () => {
    it('should fail authentication and do not try to verify anything', (done) => {
      const verifyJwtMock = sinon.stub();
      verifyJwtMock.resolves(testData.payload);

      const strategy = new Strategy(
        {
          extractToken: () => null,
          secretOrKey: 'secret',
          verifyJwt: verifyJwtMock,
        },
        (_payload, next) =>
          // Return values aren't important in this case
          next(null, {}, {})
      );

      use(strategy, done)
        .fail((info) => {
          expect(info).to.have.property('message', 'No auth token');
          sinon.assert.notCalled(verifyJwtMock);
        })
        .req((req) => {
          req.body = {};
        })
        .authenticate();
    });
  });

  describe('handling request url set to URL instead of string', () => {
    it('should fail authentication', (done) => {
      const verifyJwtMock = sinon.stub();
      verifyJwtMock.resolves(testData.payload);

      const strategy = new Strategy(
        {
          extractToken: () => null,
          secretOrKey: 'secret',
          verifyJwt: verifyJwtMock,
        },
        (_payload, next) =>
          // Return values aren't important in this case
          next(null, {}, {})
      );

      use(strategy, done)
        .fail((info) => {
          expect(info).to.have.property('message', 'No auth token');
        })
        .req((req) => {
          req.body = {};
          req.url = new URL('https://test.org/');
        })
        .authenticate();
    });
  });
});
