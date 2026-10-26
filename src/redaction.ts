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
