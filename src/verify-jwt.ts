import { verify } from 'jsonwebtoken';

export default (token, secretOrKey, options, callback) =>
  verify(token, secretOrKey, options, callback);
