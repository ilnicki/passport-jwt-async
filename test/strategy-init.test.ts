import 'mocha';
import { expect } from 'chai';

import { JwtStrategy as Strategy } from '../src/strategy';

describe('Strategy init', () => {
  it('should be named jwt', () => {
    const strategy = new Strategy(
      { extractToken: () => null, secretOrKey: 'secret' },
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

  it('should throw if constructed neither a secretOrKey or a secretOrKeyProvider arg', () => {
    expect(() => {
      new Strategy(
        { extractToken: () => null, secretOrKey: null as any },
        () => {}
      );
    }).to.throw(TypeError, 'JwtStrategy requires a secret or key');
  });

  it('should throw if constructed with both a secretOrKey and a secretOrKeyProvider', () => {
    expect(() => {
      new Strategy(
        {
          secretOrKey: 'secret',
          secretOrKeyProvider: () => 'secret',
          extractToken: () => null,
        },
        () => null
      );
    }).to.throw(TypeError);
  });

  it('should throw if constructed without a extractToken arg', () => {
    expect(() => {
      new Strategy({ secretOrKey: 'secret' } as any, () => {});
    }).to.throw(TypeError);
  });
});
