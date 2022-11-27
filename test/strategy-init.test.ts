import 'mocha';
import { expect } from 'chai';

import { JwtStrategy as Strategy } from '../src/strategy';
import { jsonWebTokenVerifier } from '../src/json-web-token-verifier';

describe('Strategy init', () => {
  it('should be named jwt', () => {
    const strategy = new Strategy(
      {
        extractToken: () => null,
        secretOrKey: 'secret',
        verifyJwt: jsonWebTokenVerifier,
      },
      () => {}
    );

    expect(strategy.name).to.equal('jwt');
  });

  it('should throw if constructed without a verify callback', () => {
    expect(() => {
      new Strategy(
        {
          extractToken: () => null,
          secretOrKey: 'secret',
        },
        null as any
      );
    }).to.throw(TypeError, 'JwtStrategy requires a verify callback');
  });

  it('should throw if constructed without a jwt verifier', () => {
    expect(() => {
      new Strategy(
        {
          extractToken: () => null,
          secretOrKey: 'secret',
        },
        () => null
      );
    }).to.throw(TypeError, 'JwtStrategy requires a token verifier');
  });

  it('should throw if constructed with both a secretOrKey and a secretOrKeyProvider', () => {
    expect(() => {
      new Strategy(
        {
          secretOrKey: 'secret',
          secretOrKeyProvider: () => 'secret',
          verifyJwt: jsonWebTokenVerifier,
          extractToken: () => null,
        },
        () => null
      );
    }).to.throw(
      TypeError,
      'JwtStrategy has been given both a secretOrKey and a secretOrKeyProvider'
    );
  });

  it('should throw if constructed without a extractToken arg', () => {
    expect(() => {
      new Strategy(
        {
          secretOrKey: 'secret',
          verifyJwt: jsonWebTokenVerifier,
          extractToken: null as any,
        },
        () => {}
      );
    }).to.throw(TypeError, 'JwtStrategy requires a jwt token extractor');
  });
});
