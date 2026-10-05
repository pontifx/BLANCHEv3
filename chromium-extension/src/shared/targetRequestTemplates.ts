const HTTP_PROTOCOLS = new Set(['http:', 'https:']);
const RAW_ASCII_CONTROL_PATTERN = /[\u0000-\u001f\u007f]/u;

/**
 * Returns the URL's query exactly as supplied, excluding the leading `?` and
 * any fragment. Values are deliberately not decoded or reserialized so that
 * duplicate keys, ordering, blank values, `+`, and percent-escape casing are
 * retained for copying and request templates.
 */
export function getTargetUrlParameters(rawUrl: string): string {
  if (RAW_ASCII_CONTROL_PATTERN.test(rawUrl)) {
    throw new TypeError('Target URLs cannot contain raw ASCII control characters.');
  }

  // Validate that the input is an absolute URL while retaining the original
  // string for extraction. URLSearchParams would normalize the query.
  new URL(rawUrl);

  const fragmentIndex = rawUrl.indexOf('#');
  const withoutFragment = fragmentIndex >= 0 ? rawUrl.slice(0, fragmentIndex) : rawUrl;
  const queryIndex = withoutFragment.indexOf('?');
  return queryIndex >= 0 ? withoutFragment.slice(queryIndex + 1) : '';
}

/** Builds a minimal Burp-ready HTTP/1.1 GET request for an HTTP(S) URL. */
export function buildBurpGetRequest(rawUrl: string): string {
  const url = parseHttpUrl(rawUrl);
  const parameters = getTargetUrlParameters(rawUrl);
  const requestTarget = `${url.pathname || '/'}${parameters ? `?${parameters}` : ''}`;

  return `GET ${requestTarget} HTTP/1.1\r\nHost: ${url.host}\r\n\r\n`;
}

/**
 * Builds a constructed form POST template by moving the URL query into the
 * request body. This does not assert that the target was observed using POST.
 */
export function buildBurpPostRequest(rawUrl: string): string {
  const url = parseHttpUrl(rawUrl);
  const body = getTargetUrlParameters(rawUrl);
  const contentLength = new TextEncoder().encode(body).byteLength;

  return (
    `POST ${url.pathname || '/'} HTTP/1.1\r\n` +
    `Host: ${url.host}\r\n` +
    'Content-Type: application/x-www-form-urlencoded\r\n' +
    `Content-Length: ${contentLength}\r\n` +
    `\r\n${body}`
  );
}

function parseHttpUrl(rawUrl: string): URL {
  const url = new URL(rawUrl);
  if (!HTTP_PROTOCOLS.has(url.protocol)) {
    throw new Error('Burp request templates require an HTTP or HTTPS target URL.');
  }
  return url;
}
