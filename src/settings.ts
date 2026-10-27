import { readFileSync } from 'node:fs';
import * as z from 'zod';
import type { Tier } from './evaluator.ts';

export class SettingsError extends Error {}

const listen = z
  .string()
  .default('0.0.0.0:8080')
  .transform((v, ctx) => {
    const match = /^\[?([^\]]*)\]?:(\d{1,5})$/.exec(v);
    if (!match) {
      ctx.addIssue({ code: 'custom', message: 'must be <host>:<port>' });
      return z.NEVER;
    }
    return { host: match[1]!, port: Number(match[2]) };
  });

const schema = z.object({
  HAMCP_POLICY: z.string().min(1, 'is required (or pass --policy)'),
  HAMCP_HA_URL: z.url({ protocol: /^https?$/ }).transform((u) => u.replace(/\/+$/, '')),
  HAMCP_LISTEN: listen,
  HAMCP_ALLOWED_ORIGINS: z
    .string()
    .default('')
    .transform((v) => new Set(v.split(',').map((o) => o.trim()).filter(Boolean))),
  HAMCP_AUDIT_READS: z.stringbool().default(false),
  HAMCP_AUDIT_WRITES: z.stringbool().default(false),
});

export type Settings = z.output<typeof schema>;

export function readSettings(env: Record<string, string | undefined>, policyFlag?: string): Settings {
  const result = schema.safeParse({ ...env, HAMCP_POLICY: policyFlag ?? env.HAMCP_POLICY ?? '' });
  if (!result.success) {
    throw new SettingsError(`Invalid settings:\n${result.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('\n')}`);
  }
  return result.data;
}

/** Reads only the HA tokens a Grant needs, so a token nobody needs is never in memory. */
export function readTokens(env: Record<string, string | undefined>, tiers: Iterable<Tier>): Map<Tier, string> {
  const tokens = new Map<Tier, string>();
  for (const tier of tiers) {
    const name = `HAMCP_HA_${tier.toUpperCase()}_TOKEN`;
    const value = env[name];
    const file = env[`${name}_FILE`];
    if (value && file) throw new SettingsError(`set ${name} or ${name}_FILE, not both`);
    const token = file ? readFileSync(file, 'utf8').trim() : value;
    if (!token) throw new SettingsError(`Policy grants an Operation that runs at the ${tier} tier; set ${name} or ${name}_FILE`);
    tokens.set(tier, token);
  }
  return tokens;
}
