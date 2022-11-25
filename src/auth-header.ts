const HEADER_SCHEME = /(\S+)\s+(\S+)/;

export interface ParsedAuthHeader {
  scheme: string;
  value: string;
}

export const parse = (header: string): ParsedAuthHeader | null => {
  if (typeof header !== 'string') {
    return null;
  }

  const matches = header.match(HEADER_SCHEME);
  return matches && { scheme: matches[1], value: matches[2] };
};
