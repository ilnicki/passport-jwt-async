const { JwtStrategy: Strategy } = require('../lib/strategy');

describe('Strategy init', () => {
  it('should be named jwt', () => {
    const strategy = new Strategy(
      { jwtFromRequest: () => {}, secretOrKey: 'secret' },
      () => {}
    );

    expect(strategy.name).to.equal('jwt');
  });

  it('should throw if constructed without a verify callback', () => {
    expect(() => {
      new Strategy({
        jwtFromRequest: () => {},
        secretOrKey: 'secret',
      });
    }).to.throw(TypeError, 'JwtStrategy requires a verify callback');
  });

  it('should throw if constructed neither a secretOrKey or a secretOrKeyProvider arg', () => {
    expect(() => {
      new Strategy({ jwtFromRequest: () => {}, secretOrKey: null }, () => {});
    }).to.throw(TypeError, 'JwtStrategy requires a secret or key');
  });

  it('should throw if constructed with both a secretOrKey and a secretOrKeyProvider', () => {
    expect(() => {
      new Strategy({
        secretOrKey: 'secret',
        secretOrKeyProvider: () => 'secret',
        jwtFromRequest: () => {},
      });
    }).to.throw(TypeError);
  });

  it('should throw if constructed without a jwtFromRequest arg', () => {
    expect(() => {
      new Strategy({ secretOrKey: 'secret' }, () => {});
    }).to.throw(TypeError);
  });
});
