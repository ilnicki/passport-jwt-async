const HEADER_SCHEME = /(\S+)\s+(\S+)/;

export const parse = (header) => {
  if (typeof header !== 'string') {
    return null;
  }

  const matches = header.match(HEADER_SCHEME);
  return matches && { scheme: matches[1], value: matches[2] };
};
