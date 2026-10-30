/** Domains whose states carry bearer URLs that open HA content to anyone, without the server. */
const TOKEN_DOMAINS = new Set(['camera', 'image', 'media_player']);

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

const stripTokenParam = (url: string) => url.replace(/(?<=[?&])token=[^&#]*(&|(?=#|$))/g, '').replace(/[?&](?=#|$)/, '');

function stripTokenParams(value: unknown): unknown {
  if (typeof value === 'string') return stripTokenParam(value);
  if (Array.isArray(value)) return value.map(stripTokenParams);
  if (isRecord(value)) return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, stripTokenParams(v)]));
  return value;
}

/** The visible marker that replaces a masked value, the one HA's own diagnostics use. */
export const REDACTED = '**REDACTED**';

/** `auth` only as a whole word, so `author` and `automation` pass; the rest anywhere in the key. */
const SECRET_KEY = /password|passwd|secret|token|api_?key|authorization|bearer|credential|private_key|cookie|webhook_id|(^|[^a-z])auth([^a-z]|$)/i;
const USERINFO = /\b([a-z][a-z0-9+.-]*:\/\/)[^\s/?#@]+@/gi;
/** A token holding a digit or symbol, so prose such as "the bearer of" is left alone. */
const BEARER = /\b(bearer\s+)(?=[\w.~+/-]*[\d.~+/-])[\w.~+/-]+=*/gi;

/**
 * Masks values under secret-looking keys, URL userinfo and `Bearer <token>`, for every read.
 * Best-effort: secrets under other keys or in other shapes pass through, as the expected-leak tests list.
 */
export function maskSecrets(value: unknown): unknown {
  if (typeof value === 'string') return value.replace(USERINFO, `$1${REDACTED}@`).replace(BEARER, `$1${REDACTED}`);
  if (Array.isArray(value)) return value.map(maskSecrets);
  if (!isRecord(value)) return value;
  return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, SECRET_KEY.test(k) ? REDACTED : maskSecrets(v)]));
}

/** The path of the first string carrying the marker, such as `actions[0].data.api_key`, so a masked value is never written back. */
export function redactedPath(value: unknown, path = ''): string | undefined {
  if (typeof value === 'string') return value.includes(REDACTED) ? path : undefined;
  const entries = Array.isArray(value)
    ? value.map((v, i) => [`${path}[${i}]`, v] as const)
    : isRecord(value)
      ? Object.entries(value).map(([k, v]) => [path ? `${path}.${k}` : k, v] as const)
      : [];
  for (const [at, v] of entries) {
    const found = redactedPath(v, at);
    if (found !== undefined) return found;
  }
  return undefined;
}

const isTokenEntity = (id: unknown) => typeof id === 'string' && /^[a-z_]+\.\w+$/.test(id) && TOKEN_DOMAINS.has(id.split('.')[0]!);

function stripAttributes(attributes: Record<string, unknown>): unknown {
  const rest = { ...attributes };
  delete rest.access_token;
  return stripTokenParams(rest);
}

/**
 * Strips `access_token` and `token=` URL parameters from every camera, image and media_player state found anywhere
 * in `value`: a state's `attributes`, or the attributes a scene config keys by entity_id. Best-effort.
 */
export function stripBearerTokens(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stripBearerTokens);
  if (!isRecord(value)) return value;
  const out = Object.fromEntries(Object.entries(value).map(([k, v]) => [k, isTokenEntity(k) && isRecord(v) ? stripAttributes(v) : stripBearerTokens(v)]));
  if (isTokenEntity(out.entity_id) && isRecord(out.attributes)) out.attributes = stripAttributes(out.attributes);
  return out;
}
