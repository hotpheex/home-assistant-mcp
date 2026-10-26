import type { Command } from './gate.ts';
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
  readonly command?: Command;
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

/** Delegating services act on whatever their data names, so only an exact name grants one. */
export const isDelegating = (service: string) => service.startsWith('homeassistant.') || service === 'scene.apply';

/** A Grant's `domain.*` never reaches a delegating service; a Deny's does, so a Deny errs wide. */
const names = (pattern: string, service: string, deny: boolean) =>
  pattern === service || (pattern.endsWith('.*') && service.startsWith(pattern.slice(0, -1)) && (deny || !isDelegating(service)));

const indicesOf = <T>(list: readonly T[], match: (item: T) => boolean) => list.flatMap((item, i) => (match(item) ? [i] : []));

export interface Selectors {
  area_id: string[];
  label_id: string[];
}

const selectorsOf = (rules: readonly { targets?: { area?: string; label?: string }[] }[]): Selectors => {
  const targets = rules.flatMap((r) => r.targets ?? []);
  return {
    area_id: [...new Set(targets.flatMap((t) => (t.area === undefined ? [] : [t.area])))],
    label_id: [...new Set(targets.flatMap((t) => (t.label === undefined ? [] : [t.label])))],
  };
};

export interface ServicePlan {
  service: string;
  /** Indices of the Caller's Grants and Denies that name the service. */
  grants: number[];
  denies: number[];
  /** The area and label selectors HA must expand: Grants with the default, Denies with config and diagnostic entities. */
  grantSelectors: Selectors;
  denySelectors: Selectors;
  /** Permits only the read-only lookups the resolver needs. */
  lookup: Allowed;
}

/** Decided by name before any I/O: no Grant naming the service, or a Deny withholding it entirely, refuses. */
export function planServiceCall(policy: Policy, caller: string, service: string): { plan: ServicePlan } | { plan: undefined; denies: number[] } {
  const grants = indicesOf(policy.grants, (g) => g.caller === caller && (g.services?.some((p) => names(p, service, false)) ?? false));
  const denies = indicesOf(policy.denies, (d) => d.caller === caller && d.services.some((p) => names(p, service, true)));
  const withheld = denies.filter((i) => policy.denies[i]!.targets === undefined);
  if (grants.length === 0 || withheld.length > 0) return { plan: undefined, denies: withheld };
  return {
    plan: {
      service,
      grants,
      denies,
      grantSelectors: selectorsOf(grants.map((i) => policy.grants[i]!)),
      denySelectors: selectorsOf(denies.map((i) => policy.denies[i]!)),
      lookup: { operation: 'service_call', tier: OPERATION_TIER.service_call } as Allowed,
    },
  };
}

/** Whether some call of the service could be allowed: a targeted one needs a Grant with Targets, a targetless one no Deny. */
export function callable(policy: Policy, caller: string, service: string, targeted: boolean): boolean {
  const { plan } = planServiceCall(policy, caller, service);
  if (!plan) return false;
  return targeted ? plan.grants.some((i) => (policy.grants[i]!.targets?.length ?? 0) > 0) : plan.denies.length === 0;
}

/** What HA expanded: the call target, the Grant selectors and the Deny selectors. */
export interface Expansion {
  targeted: boolean;
  entities: readonly string[];
  grantEntities: readonly string[];
  denyEntities: readonly string[];
}

export interface ServiceCall {
  domain: string;
  service: string;
  data: Record<string, unknown>;
  responds: boolean;
}

export type ServiceDecision =
  | { allowed: Allowed; grants: number[]; denies: []; uncovered: [] }
  | { allowed: undefined; grants: []; denies: number[]; uncovered: string[] };

export const TARGET_KEYS = ['entity_id', 'device_id', 'area_id', 'floor_id', 'label_id'] as const;

/**
 * Allows only if every target entity is covered by a Grant and by no Deny; a targetless service by name alone.
 * HA expands the union of all selectors at once, so an area or label match is credited to every rule holding one.
 */
export function decideServiceCall(policy: Policy, plan: ServicePlan, expansion: Expansion, call: ServiceCall): ServiceDecision {
  type Rule = { targets?: { domain?: string }[] };
  const matches = (rule: Rule, expanded: ReadonlySet<string>, entity: string) =>
    rule.targets?.some((t) => (t.domain === undefined ? expanded.has(entity) : t.domain === '*' || entity.startsWith(`${t.domain}.`))) ?? false;
  const granted = new Set(expansion.grantEntities);
  const withheld = new Set(expansion.denyEntities);
  const covers = (i: number, e: string) => matches(policy.grants[i]!, granted, e);
  const entities = [...new Set(expansion.entities)].sort();

  const uncovered = expansion.targeted ? entities.filter((e) => !plan.grants.some((i) => covers(i, e))) : [];
  const denies = expansion.targeted
    ? plan.denies.filter((i) => entities.some((e) => matches(policy.denies[i]!, withheld, e)))
    : plan.denies;
  if (uncovered.length > 0 || denies.length > 0) return { allowed: undefined, grants: [], denies, uncovered };

  const data = Object.fromEntries(Object.entries(call.data).filter(([k]) => !(TARGET_KEYS as readonly string[]).includes(k)));
  const command: Command = Object.freeze({
    type: 'call_service',
    domain: call.domain,
    service: call.service,
    ...(expansion.targeted ? { target: { entity_id: entities } } : {}),
    service_data: data,
    ...(call.responds ? { return_response: true } : {}),
  });
  const grants = expansion.targeted ? plan.grants.filter((i) => entities.some((e) => covers(i, e))) : plan.grants;
  return { allowed: { operation: 'service_call', tier: OPERATION_TIER.service_call, command } as Allowed, grants, denies: [], uncovered: [] };
}
