import { createHash } from 'node:crypto';
import { parse } from 'yaml';
import * as z from 'zod';

const name = z.string().regex(/^[a-z0-9_]+$/, 'must be a Home Assistant id such as living_room');

const service = z
  .string()
  .check((ctx) => {
    if (ctx.value === '*') ctx.issues.push({ code: 'custom', input: ctx.value, message: 'a bare * service is not allowed; name a domain.* or a service' });
    else if (ctx.value === 'homeassistant.*') ctx.issues.push({ code: 'custom', input: ctx.value, message: 'homeassistant services delegate to other domains; name each one exactly' });
    else if (!/^[a-z0-9_]+\.([a-z0-9_]+|\*)$/.test(ctx.value)) ctx.issues.push({ code: 'custom', input: ctx.value, message: 'must be <domain>.<service> or <domain>.*' });
  });

const target = z
  .strictObject({ domain: z.union([z.literal('*'), name]).optional(), area: name.optional(), label: name.optional() })
  .refine((t) => Object.keys(t).length === 1, 'each target holds exactly one of domain, area or label');

/** An empty list would read as "no Targets", which on a Deny errs open; omit `targets` to mean that instead. */
const targets = z.array(target).min(1, 'list at least one target, or omit targets').optional();

const grant = z
  .strictObject({
    caller: z.string(),
    read: z.enum(['plain', 'config']).optional(),
    services: z.array(service).min(1).optional(),
    targets,
    config_write: z.enum(['automation', 'script', 'scene', 'helper']).optional(),
  })
  .refine(
    (g) => [g.read, g.services, g.config_write].filter((kind) => kind !== undefined).length === 1,
    'each grant holds exactly one of read, services or config_write',
  )
  .refine((g) => g.targets === undefined || g.services !== undefined, 'targets belong only to a services grant');

const deny = z.strictObject({ caller: z.string(), services: z.array(service).min(1), targets });

const schema = z
  .strictObject({
    version: z.literal(1),
    callers: z.record(
      z.string().min(1),
      z.strictObject({
        keys: z.array(z.strictObject({ sha256: z.string().regex(/^[0-9a-f]{64}$/, 'must be 64 lowercase hex characters from keygen'), expires: z.iso.date().optional() })),
      }),
    ),
    grants: z.array(grant).default([]),
    denies: z.array(deny).default([]),
  })
  .superRefine((policy, ctx) => {
    const owner = new Map<string, string>();
    for (const [caller, { keys }] of Object.entries(policy.callers)) {
      keys.forEach(({ sha256 }, i) => {
        if (owner.has(sha256)) ctx.addIssue({ code: 'custom', path: ['callers', caller, 'keys', i, 'sha256'], message: `key hash is already bound to Caller "${owner.get(sha256)}"` });
        owner.set(sha256, caller);
      });
    }
    for (const list of ['grants', 'denies'] as const) {
      policy[list].forEach(({ caller }, i) => {
        if (!(caller in policy.callers)) ctx.addIssue({ code: 'custom', path: [list, i, 'caller'], message: `Caller "${caller}" is not declared under callers` });
      });
    }
  });

export type Policy = z.infer<typeof schema> & { readonly sha256: string };
export type Grant = Policy['grants'][number];

export class PolicyError extends Error {}

/** The Policy's shape for editors, published with each release; rules JSON Schema cannot carry, such as one kind per Grant, are left to `check`. */
export const policyJsonSchema = () => z.toJSONSchema(schema, { io: 'input' });

/** Parses a Policy file as YAML 1.2, so `on` and `off` stay strings. Throws PolicyError listing every problem. */
export function parsePolicy(text: string): Policy {
  let doc: unknown;
  try {
    doc = parse(text, { version: '1.2', schema: 'core', uniqueKeys: true });
  } catch (e) {
    throw new PolicyError(`Policy is not valid YAML: ${(e as Error).message}`);
  }
  const result = schema.safeParse(doc);
  if (!result.success) {
    const problems = result.error.issues.map((i) => `${i.path.join('.') || '(top)'}: ${i.message}`);
    throw new PolicyError(`Policy is invalid:\n${problems.join('\n')}`);
  }
  return Object.freeze({ ...result.data, sha256: createHash('sha256').update(text).digest('hex') });
}

const overlaps = (a: string, b: string) => {
  const [da, sa] = a.split('.');
  const [db, sb] = b.split('.');
  return da === db && (sa === sb || sa === '*' || sb === '*');
};

/** Policy that loads but does nothing. */
export function policyWarnings(policy: Policy, now: Date): string[] {
  const warnings: string[] = [];
  for (const [caller, { keys }] of Object.entries(policy.callers)) {
    if (!keys.some((k) => k.expires === undefined || Date.parse(k.expires) > now.getTime())) {
      warnings.push(`Caller "${caller}" has no unexpired key and can never authenticate`);
    }
  }
  policy.denies.forEach((d, i) => {
    const hit = policy.grants.some(
      (g) => g.caller === d.caller && g.services?.some((gs) => d.services.some((ds) => overlaps(gs, ds))),
    );
    if (!hit) warnings.push(`denies.${i} overlaps no grant of Caller "${d.caller}" and does nothing`);
  });
  return warnings;
}
