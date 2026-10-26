/** Domains whose states carry bearer URLs that open HA content to anyone, without the server. */
const TOKEN_DOMAINS = new Set(['camera', 'image', 'media_player']);

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

const stripTokenParam = (url: string) => url.replace(/([?&])token=[^&#]*&?/g, '$1').replace(/[?&](?=#|$)/, '');

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
 * Masks values under secret-looking keys, URL userinfo and `Bearer <token>`, for config and trace reads.
 * Best-effort: secrets under other keys or in other shapes pass through, as the expected-leak tests list.
 */
export function maskSecrets(value: unknown): unknown {
  if (typeof value === 'string') return value.replace(USERINFO, `$1${REDACTED}@`).replace(BEARER, `$1${REDACTED}`);
  if (Array.isArray(value)) return value.map(maskSecrets);
  if (!isRecord(value)) return value;
  return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, SECRET_KEY.test(k) ? REDACTED : maskSecrets(v)]));
}

/**
 * Strips `access_token` and `token=` URL parameters from every camera, image and media_player state
 * found anywhere in `value`, so states and the states inside traces both pass through it. Best-effort.
 */
export function stripBearerTokens(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stripBearerTokens);
  if (!isRecord(value)) return value;
  const out = Object.fromEntries(Object.entries(value).map(([k, v]) => [k, stripBearerTokens(v)]));
  if (typeof out.entity_id === 'string' && TOKEN_DOMAINS.has(out.entity_id.split('.')[0]!) && isRecord(out.attributes)) {
    const attributes = { ...out.attributes };
    delete attributes.access_token;
    out.attributes = stripTokenParams(attributes);
  }
  return out;
}
