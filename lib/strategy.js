const { Strategy } = require('passport-strategy');

/**
 * Strategy constructor
 *
 * @param options
 *          secretOrKey: String or buffer containing the secret or PEM-encoded public key. Required unless secretOrKeyProvider is provided.
 *          secretOrKeyProvider: callback in the format secretOrKeyProvider(request, rawJwtToken, done)`,
 *                               which should call done with a secret or PEM-encoded public key
 *                               (asymmetric) for the given undecoded jwt token string and  request
 *                               combination. done has the signature function done(err, secret).
 *                               REQUIRED unless `secretOrKey` is provided.
 *          jwtFromRequest: (REQUIRED) Function that accepts a request as the only parameter and returns the either JWT as a string or null
 *          issuer: If defined issuer will be verified against this value
 *          audience: If defined audience will be verified against this value
 *          algorithms: List of strings with the names of the allowed algorithms. For instance, ["HS256", "HS384"].
 *          ignoreExpiration: if true do not validate the expiration of the token.
 *          passReqToCallback: If true the verify callback will be called with args (request, jwt_payload, done_callback).
 * @param verify - Verify callback with args (jwt_payload, done_callback) if passReqToCallback is false,
 *                 (request, jwt_payload, done_callback) if true.
 */
class JwtStrategy extends Strategy {
  /**
   * Allow for injection of JWT Verifier.
   *
   * This improves testability by allowing tests to cleanly isolate failures in the JWT Verification
   * process from failures in the passport related mechanics of authentication.
   *
   * Note that this should only be replaced in tests.
   */
  static JwtVerifier = require('./verify-jwt');

  constructor(options, verify) {
    super();

    this.name = 'jwt';

    this._secretOrKeyProvider = options.secretOrKeyProvider;

    if (options.secretOrKey) {
      if (this._secretOrKeyProvider) {
        throw new TypeError(
          'JwtStrategy has been given both a secretOrKey and a secretOrKeyProvider'
        );
      }
      this._secretOrKeyProvider = function (request, rawJwtToken, done) {
        done(null, options.secretOrKey);
      };
    }

    if (!this._secretOrKeyProvider) {
      throw new TypeError('JwtStrategy requires a secret or key');
    }

    this._verify = verify;
    if (!this._verify) {
      throw new TypeError('JwtStrategy requires a verify callback');
    }

    this._jwtFromRequest = options.jwtFromRequest;
    if (!this._jwtFromRequest) {
      throw new TypeError(
        'JwtStrategy requires a function to retrieve jwt from requests (see option jwtFromRequest)'
      );
    }

    this._passReqToCallback = options.passReqToCallback;
    const jsonWebTokenOptions = options.jsonWebTokenOptions || {};
    //for backwards compatibility, still allowing you to pass
    //audience / issuer / algorithms / ignoreExpiration
    //on the options.
    this._verifOpts = Object.assign({}, jsonWebTokenOptions, {
      audience: options.audience,
      issuer: options.issuer,
      algorithms: options.algorithms,
      ignoreExpiration: !!options.ignoreExpiration,
    });
  }

  /**
   * Authenticate request based on JWT obtained from header or post body
   */
  authenticate(req, options) {
    const self = this;

    const token = self._jwtFromRequest(req);

    if (!token) {
      return self.fail(new Error('No auth token'));
    }

    this._secretOrKeyProvider(
      req,
      token,
      function (secretOrKeyError, secretOrKey) {
        if (secretOrKeyError) {
          self.fail(secretOrKeyError);
        } else {
          // Verify the JWT
          JwtStrategy.JwtVerifier(
            token,
            secretOrKey,
            self._verifOpts,
            function (jwt_err, payload) {
              if (jwt_err) {
                return self.fail(jwt_err);
              } else {
                // Pass the parsed token to the user
                const verified = function (err, user, info) {
                  if (err) {
                    return self.error(err);
                  } else if (!user) {
                    return self.fail(info);
                  } else {
                    return self.success(user, info);
                  }
                };

                try {
                  if (self._passReqToCallback) {
                    self._verify(req, payload, verified);
                  } else {
                    self._verify(payload, verified);
                  }
                } catch (ex) {
                  self.error(ex);
                }
              }
            }
          );
        }
      }
    );
  }
}

/**
 * Export the Jwt Strategy
 */
module.exports = JwtStrategy;
