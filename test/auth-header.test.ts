import 'mocha';
import { expect } from 'chai';

import { parse } from '../src/auth-header';

describe('Auth Header Parser', () => {
  it('should handle single space separated values', () => {
    const res = parse('SCHEME VALUE');
    expect(res).to.deep.equal({ scheme: 'SCHEME', value: 'VALUE' });
  });

  it('should handle CRLF separator', () => {
    const res = parse('SCHEME\nVALUE');
    expect(res).to.deep.equal({ scheme: 'SCHEME', value: 'VALUE' });
  });

  it('should handle malformed authentication headers with no scheme', () => {
    const res = parse('malformed');
    expect(res).to.not.be.ok;
  });

  it('should return null when the auth header is not a string', () => {
    const res = parse({} as string);
    expect(res).to.be.null;
  });
});
