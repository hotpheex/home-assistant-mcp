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
