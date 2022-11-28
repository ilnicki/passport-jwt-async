import { Request } from 'express';
import { Strategy } from 'passport-strategy';
import { TokenExtractor } from './extract-jwt';
import { JwtPayload } from './jwt-payload';

export type SecretOrKeyProvider = (
  request: Request,
  rawJwtToken: string
) => Promise<string | Buffer | undefined>;

export type VerifyCallback = (
  result: {
    payload: any;
    request?: Request;
  },
  done: (err: Error | null, user?: any, info?: any) => void
) => void;

export type JwtVerifier<T extends object> = (params: {
  token: string;
  secretOrKey?: string | Buffer;
  options?: T;
}) => Promise<JwtPayload>;

export interface JwtStrategyOptions<T extends object> {
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
   * A function to verify and decode token body.
   */
  verifyJwt?: JwtVerifier<T>;

  verifyJwtOptions?: T;
}

export class JwtStrategy<T extends object = any> extends Strategy {
  private verifyJwt: JwtVerifier<T>;
  private verifyJwtOptions?: T;

  private secretOrKeyProvider: SecretOrKeyProvider;
  private extractToken: TokenExtractor;
  private passReqToCallback: boolean;

  public name = 'jwt';

  constructor(
    {
      verifyJwt,
      secretOrKeyProvider,
      secretOrKey,
      passReqToCallback = false,
      verifyJwtOptions,
      extractToken,
    }: JwtStrategyOptions<T>,
    private readonly verify: VerifyCallback
  ) {
    super();

    this.passReqToCallback = passReqToCallback;
    if (!this.verify) {
      throw new TypeError('JwtStrategy requires a verify callback');
    }

    if (!verifyJwt) {
      throw new TypeError('JwtStrategy requires a token verifier');
    }
    this.verifyJwt = verifyJwt;
    this.verifyJwtOptions = verifyJwtOptions;

    this.secretOrKeyProvider = secretOrKeyProvider ?? (async () => secretOrKey);

    this.extractToken = extractToken;
    if (!this.extractToken) {
      throw new TypeError('JwtStrategy requires a jwt token extractor');
    }
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
  public async authenticate(request: Request): Promise<void> {
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
        return this.error(verifyError as Error);
      }
    } catch (secretOrKeyError) {
      return this.fail(secretOrKeyError, 401);
    }
  }
}
