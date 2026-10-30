import type { Command, RestRequest } from './gate.ts';
import type { Grant, Policy } from './policy.ts';

export type Tier = 'users' | 'admin';
export type Operation = 'plain_read' | 'config_read' | 'service_call' | 'config_write';
export type ReadKind = 'plain_read' | 'config_read';

/** In code, not Policy, so no Grant can move an Operation onto the admin token. */
export const OPERATION_TIER = {
  plain_read: 'users',
  config_read: 'admin',
  service_call: 'users',
  config_write: 'admin',
} as const satisfies Record<Operation, Tier>;

export type WebSocketWrite = { readonly via: 'websocket'; readonly command: Command };
/** The exact write a decision permits: a WebSocket command, or a request to HA's config REST API. */
export type Write = WebSocketWrite | { readonly via: 'rest'; readonly request: RestRequest };

declare const issued: unique symbol;
/** A decision to send; the gate sends nothing else, and only this module can construct one. */
export interface Allowed {
  readonly [issued]: true;
  readonly operation: Operation;
  readonly tier: Tier;
  readonly write?: Write;
}

/** Every Allowed this module issued; the type brand is only a compile-time signal, so the gate checks here at runtime. */
const issuedDecisions = new WeakSet<Allowed>();
export const isIssued = (allowed: Allowed) => issuedDecisions.has(allowed);

function deepFreeze<T>(value: T): T {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const v of Object.values(value)) deepFreeze(v);
  return value;
}

/** A frozen copy, so nothing the caller still holds can change what was checked, recorded as issued. */
function issue<D extends Omit<Allowed, typeof issued>>(decision: D): Allowed & D {
  const allowed = deepFreeze(structuredClone(decision)) as Allowed & D;
  issuedDecisions.add(allowed);
  return allowed;
}

/** Every Operation a Grant gives: a write also gives plain read, and a config write also gives config read. */
export function operationsOf(grant: Grant): Operation[] {
  if (grant.read === 'plain') return ['plain_read'];
  if (grant.read === 'config') return ['config_read'];
  if (grant.services) return ['service_call', 'plain_read'];
  return ['config_write', 'config_read', 'plain_read'];
}

const indicesOf = <T>(list: readonly T[], match: (item: T) => boolean) => list.flatMap((item, i) => (match(item) ? [i] : []));

/** The indices of the Caller's Grants that give `operation`. */
export const grantsFor = (policy: Policy, caller: string, operation: Operation) =>
  indicesOf(policy.grants, (g) => g.caller === caller && operationsOf(g).includes(operation));

export function neededTiers(policy: Policy): Set<Tier> {
  return new Set(policy.grants.flatMap((g) => operationsOf(g).map((op) => OPERATION_TIER[op])));
}

export type ReadDecision = { allowed: Allowed; grants: number[] } | { allowed: undefined; grants: [] };

const readOf = (grants: number[], kind: ReadKind): ReadDecision =>
  grants.length === 0 ? { allowed: undefined, grants: [] } : { allowed: issue({ operation: kind, tier: OPERATION_TIER[kind] }), grants };

/** A read is decided by the Caller and the read kind alone. */
export const decideRead = (policy: Policy, caller: string, kind: ReadKind) => readOf(grantsFor(policy, caller, kind), kind);

/** Resolving Policy names, for `check` and startup warnings, may send only plain read's read-only commands, at its tier. */
export const NAME_LOOKUP = issue({ operation: 'plain_read', tier: OPERATION_TIER.plain_read });

/** Delegating services act on whatever their data names, so only an exact name grants one. */
export const isDelegating = (service: string) => service.startsWith('homeassistant.') || service === 'scene.apply';

/** A Grant's `domain.*` never reaches a delegating service; a Deny's does, so a Deny errs wide. */
const names = (pattern: string, service: string, deny: boolean) =>
  pattern === service || (pattern.endsWith('.*') && service.startsWith(pattern.slice(0, -1)) && (deny || !isDelegating(service)));

export interface Selectors {
  area_id: string[];
  label_id: string[];
}

export const selectorsOf = (rules: readonly { targets?: { area?: string; label?: string }[] }[]): Selectors => {
  const targets = rules.flatMap((r) => r.targets ?? []);
  return { area_id: [...new Set(targets.flatMap((t) => t.area ?? []))], label_id: [...new Set(targets.flatMap((t) => t.label ?? []))] };
};

export interface ServicePlan {
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
      grants,
      denies,
      grantSelectors: selectorsOf(grants.map((i) => policy.grants[i]!)),
      denySelectors: selectorsOf(denies.map((i) => policy.denies[i]!)),
      lookup: issue({ operation: 'service_call', tier: OPERATION_TIER.service_call }),
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

interface ServiceCall {
  domain: string;
  service: string;
  data: Record<string, unknown>;
  responds: boolean;
}

export type ServiceDecision =
  | { allowed: Allowed & { write: WebSocketWrite }; grants: number[]; denies: []; uncovered: [] }
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
  const command: Command = {
    type: 'call_service',
    domain: call.domain,
    service: call.service,
    ...(expansion.targeted ? { target: { entity_id: entities } } : {}),
    service_data: data,
    ...(call.responds ? { return_response: true } : {}),
  };
  const grants = expansion.targeted ? plan.grants.filter((i) => entities.some((e) => covers(i, e))) : plan.grants;
  return { allowed: issue({ operation: 'service_call', tier: OPERATION_TIER.service_call, write: { via: 'websocket', command } }), grants, denies: [], uncovered: [] };
}

export type ConfigKind = NonNullable<Grant['config_write']>;
export const HELPER_DOMAINS = ['input_boolean', 'input_number', 'input_select', 'input_text', 'input_datetime', 'input_button', 'counter', 'timer', 'schedule'] as const;

export const configPath = (kind: ConfigKind, id: string) => `/api/config/${kind}/config/${encodeURIComponent(id)}`;
/** A helper's config id is unique only within its domain, so the server names it `<domain>.<id>`. */
export const splitHelperId = (id: string) => [id.slice(0, id.indexOf('.')), id.slice(id.indexOf('.') + 1)] as const;

const writersOf = (policy: Policy, caller: string, kind: ConfigKind) => indicesOf(policy.grants, (g) => g.caller === caller && g.config_write === kind);

/** Automation and script config is config read; scene and helper config only a config write of that kind gives. */
export const decideConfigRead = (policy: Policy, caller: string, kind: ConfigKind) =>
  readOf(kind === 'automation' || kind === 'script' ? grantsFor(policy, caller, 'config_read') : writersOf(policy, caller, kind), 'config_read');

export interface ConfigWrite {
  kind: ConfigKind;
  action: 'create' | 'update' | 'delete';
  /** A config id or script key; for a helper, `<domain>.<id>`. */
  id: string;
  config?: Record<string, unknown>;
}

/** HA's config REST for automations, scripts and scenes; the helper domain's own WebSocket commands for a helper. */
function writeOf({ kind, action, id, config = {} }: ConfigWrite): Write {
  const rest = (request: RestRequest) => ({ via: 'rest', request }) as const;
  if (kind !== 'helper') return rest(action === 'delete' ? { method: 'DELETE', path: configPath(kind, id) } : { method: 'POST', path: configPath(kind, id), body: config });
  const [domain, item] = splitHelperId(id);
  if (action === 'create') return { via: 'websocket', command: { ...config, type: `${domain}/create` } };
  return { via: 'websocket', command: { ...(action === 'update' && config), type: `${domain}/${action}`, [`${domain}_id`]: item } };
}

export type ConfigWriteDecision = { allowed: Allowed & { write: Write }; grants: number[] } | { allowed: undefined; grants: [] };

/** A config write needs a config-write Grant of its kind; the Allowed names the exact request. */
export function decideConfigWrite(policy: Policy, caller: string, write: ConfigWrite): ConfigWriteDecision {
  const grants = writersOf(policy, caller, write.kind);
  if (grants.length === 0) return { allowed: undefined, grants: [] };
  return { allowed: issue({ operation: 'config_write', tier: OPERATION_TIER.config_write, write: writeOf(write) }), grants };
}

/** HA replaces a whole entry on update, so an allowed update is reissued over the stored config it changes; a helper's update schema takes no `id`. */
export function mergedUpdate(allowed: Allowed, stored: Record<string, unknown>): Allowed & { write: Write } {
  const { write } = allowed;
  if (isIssued(allowed) && write?.via === 'rest' && write.request.method === 'POST') {
    return issue({ ...allowed, write: { via: 'rest', request: { ...write.request, body: { ...stored, ...(write.request.body as object) } } } });
  }
  if (isIssued(allowed) && write?.via === 'websocket' && write.command.type.endsWith('/update')) {
    const item = Object.fromEntries(Object.entries(stored).filter(([k]) => k !== 'id'));
    return issue({ ...allowed, write: { via: 'websocket', command: { ...item, ...write.command } } });
  }
  throw new Error('only an issued config update merges');
}
