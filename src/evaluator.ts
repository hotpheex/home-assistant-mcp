import type { Command, RestRequest } from './gate.ts';
import type { Grant, Policy } from './policy.ts';

export type Tier = 'users' | 'admin';
export type Operation = 'plain_read' | 'config_read' | 'service_call' | 'config_write';
export type ReadKind = 'plain_read' | 'config_read';

/** Fixed in code: nothing runs at admin unless its Operation's tier is admin. */
export const OPERATION_TIER = {
  plain_read: 'users',
  config_read: 'admin',
  service_call: 'users',
  config_write: 'admin',
} as const satisfies Record<Operation, Tier>;

declare const issued: unique symbol;
/** A decision to send; the gate sends nothing else, and only this module can construct one. */
export interface Allowed {
  readonly [issued]: true;
  readonly operation: Operation;
  readonly tier: Tier;
  /** The exact write this decision permits, if any. */
  readonly command?: Command | RestRequest;
}

/** Every Operation a Grant gives: a write also gives plain read, and a config write also gives config read. */
export function operationsOf(grant: Grant): Operation[] {
  if (grant.read === 'plain') return ['plain_read'];
  if (grant.read === 'config') return ['config_read'];
  if (grant.services) return ['service_call', 'plain_read'];
  return ['config_write', 'config_read', 'plain_read'];
}

/** The indices of the Caller's Grants that give `operation`; empty means the Caller lacks it. */
export function grantsFor(policy: Policy, caller: string, operation: Operation): number[] {
  return policy.grants.flatMap((g, i) => (g.caller === caller && operationsOf(g).includes(operation) ? [i] : []));
}

export function neededTiers(policy: Policy): Set<Tier> {
  return new Set(policy.grants.flatMap((g) => operationsOf(g).map((op) => OPERATION_TIER[op])));
}

export type ReadDecision = { allowed: Allowed; grants: number[] } | { allowed: undefined; grants: [] };

/** A read is decided by the Caller and the read kind alone. */
export function decideRead(policy: Policy, caller: string, kind: ReadKind): ReadDecision {
  const grants = grantsFor(policy, caller, kind);
  if (grants.length === 0) return { allowed: undefined, grants: [] };
  return { allowed: { operation: kind, tier: OPERATION_TIER[kind] } as Allowed, grants };
}

export type ConfigKind = NonNullable<Grant['config_write']>;
/** What a `helper` config write covers: input_*, counter, timer and schedule. */
export const HELPER_DOMAINS = ['input_boolean', 'input_number', 'input_select', 'input_text', 'input_datetime', 'input_button', 'counter', 'timer', 'schedule'] as const;

export const configPath = (kind: ConfigKind, id: string) => `/api/config/${kind}/config/${encodeURIComponent(id)}`;

const writersOf = (policy: Policy, caller: string, kind: ConfigKind) =>
  policy.grants.flatMap((g, i) => (g.caller === caller && g.config_write === kind ? [i] : []));

/** Automation and script config is config read; scene and helper config only a config write of that kind gives. */
export function decideConfigRead(policy: Policy, caller: string, kind: ConfigKind): ReadDecision {
  if (kind === 'automation' || kind === 'script') return decideRead(policy, caller, 'config_read');
  const grants = writersOf(policy, caller, kind);
  if (grants.length === 0) return { allowed: undefined, grants: [] };
  return { allowed: { operation: 'config_read', tier: OPERATION_TIER.config_read } as Allowed, grants };
}

export interface ConfigWrite {
  kind: ConfigKind;
  action: 'create' | 'update' | 'delete';
  /** A config id or script key; for a helper, `<domain>.<id>`. */
  id: string;
  config?: Record<string, unknown>;
}

/** HA's config REST for automations, scripts and scenes; the helper domain's own WebSocket commands for a helper. */
function requestOf({ kind, action, id, config = {} }: ConfigWrite): Command | RestRequest {
  if (kind !== 'helper') return action === 'delete' ? { method: 'DELETE', path: configPath(kind, id) } : { method: 'POST', path: configPath(kind, id), body: config };
  const [domain, item] = [id.slice(0, id.indexOf('.')), id.slice(id.indexOf('.') + 1)];
  if (action === 'create') return { ...config, type: `${domain}/create` };
  return { ...(action === 'update' && config), type: `${domain}/${action}`, [`${domain}_id`]: item };
}

/** A config write needs a config-write Grant of its kind; the Allowed names the exact request. */
export function decideConfigWrite(policy: Policy, caller: string, write: ConfigWrite): ReadDecision {
  const grants = writersOf(policy, caller, write.kind);
  if (grants.length === 0) return { allowed: undefined, grants: [] };
  return { allowed: { operation: 'config_write', tier: OPERATION_TIER.config_write, command: Object.freeze(requestOf(write)) } as Allowed, grants };
}
