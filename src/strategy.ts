import { Request } from 'express';
import { Strategy } from 'passport-strategy';
import { TokenExtractor } from './extract-jwt';
import JwtVerifier from './verify-jwt';

export type SecretOrKeyProvider = (
  request: Request,
  rawJwtToken: string
) => string | Buffer | Promise<string | Buffer>;

export type VerifyCallback = (
  result: {
    payload: any;
    request?: Request;
  },
  done: (err: unknown, user, info) => void
) => void;

export interface JwtStrategyOptions {
  /**
   * String or buffer containing the secret or PEM-encoded public key.
   * Required unless secretOrKeyProvider is provided.
   */
  secretOrKey: string | Buffer;

  /**
   * Callback in the format secretOrKeyProvider(request, rawJwtToken, done)`,
   * which should call done with a secret or PEM-encoded public key
   * (asymmetric) for the given undecoded jwt token string and  request
   * combination. done has the signature function done(err, secret).
   * REQUIRED unless `secretOrKey` is provided.
   */
  secretOrKeyProvider: SecretOrKeyProvider;

  /**
   * Function that accepts a request as the only parameter and returns
   * the either JWT as a string or null
   */
  jwtFromRequest: any;

  /**
   * If defined issuer will be verified against this value
   */
  issuer: string;

  /**
   * If defined audience will be verified against this value
   */
  audience: string;

  /**
   * List of strings with the names of the allowed algorithms. For instance, ["HS256", "HS384"].
   */
  algorithms: string[];

  /**
   * If true do not validate the expiration of the token.
   */
  ignoreExpiration: boolean;

  /**
   * If true the verify callback will be called with args (request, jwt_payload, done_callback).
   */
  passReqToCallback: boolean;

  verifyJwt: any;

  verifyJwtOptions: any;
}

/**
 * Strategy constructor
 *
 * @param options
 *
 * @param verify - Verify callback with args (jwt_payload, done_callback) if passReqToCallback is false,
 *                 (request, jwt_payload, done_callback) if true.
 */
export class JwtStrategy extends Strategy {
  private verifyJwt: any;
  private verifyJwtOptions: any;

  private secretOrKeyProvider: SecretOrKeyProvider;
  private jwtFromRequest: TokenExtractor;
  private passReqToCallback: boolean;

  public name = 'jwt';

  constructor(
    {
      verifyJwt = JwtVerifier,
      secretOrKeyProvider,
      secretOrKey,
      passReqToCallback = false,
      verifyJwtOptions = {},
      jwtFromRequest,
    }: JwtStrategyOptions,
    private readonly verify: VerifyCallback
  ) {
    super();

    if (!this.verify) {
      throw new TypeError('JwtStrategy requires a verify callback');
    }

    this.verifyJwt = verifyJwt;

    this.secretOrKeyProvider = secretOrKeyProvider;

    if (secretOrKey) {
      if (this.secretOrKeyProvider) {
        throw new TypeError(
          'JwtStrategy has been given both a secretOrKey and a secretOrKeyProvider'
        );
      }
      this.secretOrKeyProvider = () => secretOrKey;
    }

    if (!this.secretOrKeyProvider) {
      throw new TypeError('JwtStrategy requires a secret or key');
    }

    this.jwtFromRequest = jwtFromRequest;
    if (!this.jwtFromRequest) {
      throw new TypeError(
        'JwtStrategy requires a function to retrieve jwt from requests (see option jwtFromRequest)'
      );
    }

    this.passReqToCallback = passReqToCallback;
    this.verifyJwtOptions = verifyJwtOptions;
  }

  /**
   * Authenticate request based on JWT obtained from header or post body
   */
  public async authenticate(request: Request, options): Promise<void> {
    const token = this.jwtFromRequest(request);

    if (!token) {
      return this.fail(new Error('No auth token'), 401);
    }

    try {
      const secretOrKey = await this.secretOrKeyProvider(request, token);

      this.verifyJwt(
        token,
        secretOrKey,
        this.verifyJwtOptions,
        (jwtError, payload) => {
          if (jwtError) {
            return this.fail(jwtError);
          } else {
            // Pass the parsed token to the user
            const verified = (err, user, info) => {
              if (err) {
                return this.error(err);
              } else if (!user) {
                return this.fail(info);
              } else {
                return this.success(user, info);
              }
            };

            try {
              if (this.passReqToCallback) {
                this.verify({ request, payload }, verified);
              } else {
                this.verify({ payload }, verified);
              }
            } catch (ex) {
              this.error(ex);
            }
          }
        }
      );
    } catch (secretOrKeyError) {
      this.fail(secretOrKeyError, 401);
    }
  }
}
