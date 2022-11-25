import { verify } from 'jsonwebtoken';

export default (
  token: string,
  secretOrKey: string | Buffer,
  options,
  callback
) => verify(token, secretOrKey, options, callback);
