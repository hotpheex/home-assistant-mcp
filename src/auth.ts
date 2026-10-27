import { createHash, timingSafeEqual } from 'node:crypto';
import type { Policy } from './policy.ts';

export type Authenticated = { ok: true; caller: string; keyHashPrefix: string };
export type Unauthenticated = {
  ok: false;
  reason: 'missing' | 'malformed' | 'unknown' | 'expired';
  caller?: string;
  keyHashPrefix?: string;
};

const KEY = /^hamcp_[A-Za-z0-9_-]{43}$/;

export const hashKey = (key: string) => createHash('sha256').update(key).digest();

/** Every failure reason gets the same 401; only the Audit record tells them apart. */
export function authenticator(policy: Policy) {
  const keys = Object.entries(policy.callers).flatMap(([caller, { keys }]) =>
    keys.map((k) => ({ caller, hash: Buffer.from(k.sha256, 'hex'), prefix: k.sha256.slice(0, 8), expires: k.expires })),
  );
  return (authorization: string | undefined, now: Date): Authenticated | Unauthenticated => {
    if (authorization === undefined) return { ok: false, reason: 'missing' };
    const key = /^Bearer (\S+)$/i.exec(authorization)?.[1];
    if (key === undefined || !KEY.test(key)) return { ok: false, reason: 'malformed' };
    const hash = hashKey(key);
    // Compare against every key so the time taken does not reveal which one matched.
    let match: (typeof keys)[number] | undefined;
    for (const k of keys) if (timingSafeEqual(k.hash, hash)) match = k;
    if (!match) return { ok: false, reason: 'unknown' };
    const found = { caller: match.caller, keyHashPrefix: match.prefix };
    if (match.expires !== undefined && now.getTime() >= Date.parse(match.expires)) return { ok: false, reason: 'expired', ...found };
    return { ok: true, ...found };
  };
}

const EXPIRY_WARNING_MS = 14 * 86_400_000;

/** Keys that still work but stop within 14 days, so the deployer rotates them in time. */
export function expiryWarnings(policy: Policy, now: Date): string[] {
  return Object.entries(policy.callers).flatMap(([caller, { keys }]) =>
    keys.flatMap(({ sha256, expires }) => {
      const left = expires === undefined ? Infinity : Date.parse(expires) - now.getTime();
      return left > 0 && left <= EXPIRY_WARNING_MS ? [`Caller "${caller}" key ${sha256.slice(0, 8)} expires on ${expires}; add a new key and move the Caller to it`] : [];
    }),
  );
}
