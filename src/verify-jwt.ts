import { JwtPayload, verify } from 'jsonwebtoken';
import type { JwtVerifier } from './strategy';

export const auth0JwtVerifier: JwtVerifier = ({
  token,
  secretOrKey,
  options,
}) =>
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
