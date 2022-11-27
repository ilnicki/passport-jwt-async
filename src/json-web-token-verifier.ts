import { verify, VerifyOptions } from 'jsonwebtoken';
import { JwtPayload } from './jwt-payload';
import { JwtVerifier } from './strategy';

export const jsonWebTokenVerifier: JwtVerifier<
  Exclude<VerifyOptions, 'complete'>
> = ({ token, secretOrKey, options = {} }) =>
  new Promise((resolve, reject) => {
    verify(
      token,
      secretOrKey,
      { ...options, complete: false },
      (error, decoded) => {
        if (error) {
          return reject(error);
        }

        return resolve(decoded as JwtPayload);
      }
    );
  });
