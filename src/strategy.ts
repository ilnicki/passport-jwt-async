import { Request } from 'express';
import { JwtPayload } from 'jsonwebtoken';
import { Strategy } from 'passport-strategy';
import { TokenExtractor } from './extract-jwt';
import { auth0JwtVerifier } from './verify-jwt';

export type SecretOrKeyProvider = (
  request: Request,
  rawJwtToken: string
) => string | Buffer | Promise<string | Buffer>;

export type VerifyCallback = (
  result: {
    payload: any;
    request?: Request;
  },
  done: (err: Error | null, user?: any, info?: any) => void
) => void;

export type JwtVerifier = (params: {
  token: string;
  secretOrKey: string | Buffer;
  options: object;
}) => Promise<JwtPayload>;

export interface JwtStrategyOptions {
  /**
   * String or buffer containing the secret or PEM-encoded public key.
   * Required unless secretOrKeyProvider is provided.
   */
  secretOrKey?: string | Buffer;

  /**
   * Callback in the format secretOrKeyProvider(request, rawJwtToken)`,
   * which should call done with a secret or PEM-encoded public key
   * (asymmetric) for the given undecoded jwt token string and  request
   * combination. done has the signature function done(err, secret).
   * REQUIRED unless `secretOrKey` is provided.
   */
  secretOrKeyProvider?: SecretOrKeyProvider;

  /**
   * Function that accepts a request as the only parameter and returns
   * the either JWT as a string or null
   */
  extractToken: TokenExtractor;

  /**
   * If true the verify callback will be called with args (request, jwt_payload, done_callback).
   */
  passReqToCallback?: boolean;

  /**
   *
   */
  verifyJwt?: JwtVerifier;

  verifyJwtOptions?: {
    /**
     * If defined issuer will be verified against this value
     */
    issuer?: string;

    /**
     * If defined audience will be verified against this value
     */
    audience?: string;

    /**
     * List of strings with the names of the allowed algorithms. For instance, ["HS256", "HS384"].
     */
    algorithms?: string[];

    /**
     * If true do not validate the expiration of the token.
     */
    ignoreExpiration?: boolean;

    clockTolerance?: number;

    maxAge?: string;
  };
}

export class JwtStrategy extends Strategy {
  private verifyJwt: JwtVerifier;
  private verifyJwtOptions: object;

  private secretOrKeyProvider: SecretOrKeyProvider;
  private extractToken: TokenExtractor;
  private passReqToCallback: boolean;

  public name = 'jwt';

  constructor(
    {
      verifyJwt = auth0JwtVerifier,
      secretOrKeyProvider,
      secretOrKey,
      passReqToCallback = false,
      verifyJwtOptions = {},
      extractToken,
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

    this.extractToken = extractToken;
    if (!this.extractToken) {
      throw new TypeError(
        'JwtStrategy requires a function to retrieve jwt from requests (see option extractToken)'
      );
    }

    this.passReqToCallback = passReqToCallback;
    this.verifyJwtOptions = verifyJwtOptions;
  }

  private async verifyAsync(
    params: Parameters<VerifyCallback>[0]
  ): Promise<{ user?: any; info?: any }> {
    return new Promise((resolve, reject) => {
      try {
        this.verify(params, (err, user, info) => {
          if (err) {
            return reject(err);
          }

          return resolve({ user, info });
        });
      } catch (err) {
        return reject(err);
      }
    });
  }

  /**
   * Authenticate request based on JWT obtained from header or post body
   */
  public async authenticate(request: Request, options): Promise<void> {
    const token = this.extractToken(request);

    if (!token) {
      return this.fail(new Error('No auth token'), 401);
    }

    try {
      const secretOrKey = await this.secretOrKeyProvider(request, token);
      const payload = await this.verifyJwt({
        token,
        secretOrKey,
        options: this.verifyJwtOptions,
      });

      try {
        const { user, info } = await this.verifyAsync({
          payload,
          ...(this.passReqToCallback && { request }),
        });

        if (!user) {
          return this.fail(info);
        }

        return this.success(user, info);
      } catch (verifyError) {
        return this.error(verifyError);
      }
    } catch (secretOrKeyError) {
      return this.fail(secretOrKeyError, 401);
    }
  }
}
