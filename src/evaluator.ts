import {
  COLLECTION_UPDATE_COMMANDS,
  collectionOf,
  configPath,
  dashboardPath,
  ENTITY_NAME_FIELDS,
  FLOW_ID,
  FLOW_PATH,
  isSafeConfigId,
  OPTIONS_PATH,
  TARGET_KEYS,
  type Command,
  type RestRequest,
} from './ha.ts';
import type { ConfigKind, Grant, Policy } from './policy.ts';

export type { ConfigKind };
export type Tier = 'users' | 'admin';
export type Operation = 'plain_read' | 'config_read' | 'service_call' | 'config_write';
type ReadKind = 'plain_read' | 'config_read';

const OPERATION_TIER = {
  plain_read: 'users',
  config_read: 'admin',
  service_call: 'users',
  config_write: 'admin',
} as const satisfies Record<Operation, Tier>;

type WebSocketWrite = { readonly via: 'websocket'; readonly command: Command };
type Write = WebSocketWrite | { readonly via: 'rest'; readonly request: RestRequest };

declare const issued: unique symbol;
export interface Allowed {
  readonly [issued]: true;
  readonly operation: Operation;
  readonly tier: Tier;
  readonly write?: Write;
}

const issuedDecisions = new WeakSet<Allowed>();
export const isIssued = (allowed: Allowed) => issuedDecisions.has(allowed);

function deepFreeze<T>(value: T): T {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const v of Object.values(value)) deepFreeze(v);
  return value;
}

function issue<D extends Omit<Allowed, typeof issued>>(decision: D): Allowed & D {
  const allowed = deepFreeze(structuredClone(decision)) as Allowed & D;
  issuedDecisions.add(allowed);
  return allowed;
}

function operationsOf(grant: Grant): Operation[] {
  if (grant.read === 'plain') return ['plain_read'];
  if (grant.read === 'config') return ['config_read'];
  if (grant.services) return ['service_call', 'plain_read'];
  return ['config_write', 'config_read', 'plain_read'];
}

const indicesOf = <T>(list: readonly T[], match: (item: T) => boolean) => list.flatMap((item, i) => (match(item) ? [i] : []));

export const grantsFor = (policy: Policy, caller: string, operation: Operation) =>
  indicesOf(policy.grants, (g) => g.caller === caller && operationsOf(g).includes(operation));

export function neededTiers(policy: Policy): Set<Tier> {
  return new Set(policy.grants.flatMap((g) => operationsOf(g).map((op) => OPERATION_TIER[op])));
}

type ReadDecision = { allowed: Allowed; grants: number[] } | { allowed: undefined; grants: [] };

const readOf = (grants: number[], kind: ReadKind): ReadDecision =>
  grants.length === 0 ? { allowed: undefined, grants: [] } : { allowed: issue({ operation: kind, tier: OPERATION_TIER[kind] }), grants };

export const decideRead = (policy: Policy, caller: string, kind: ReadKind) => readOf(grantsFor(policy, caller, kind), kind);

export const NAME_LOOKUP = issue({ operation: 'plain_read', tier: OPERATION_TIER.plain_read });

export const isDelegating = (service: string) => service.startsWith('homeassistant.') || service === 'scene.apply';

const matchesServicePattern = (pattern: string, service: string, { includeDelegating }: { includeDelegating: boolean }) =>
  pattern === service || (pattern.endsWith('.*') && service.startsWith(pattern.slice(0, -1)) && (includeDelegating || !isDelegating(service)));

export interface Selectors {
  area_id: string[];
  label_id: string[];
}

export const selectorsOf = (rules: readonly { targets?: { area?: string; label?: string }[] }[]): Selectors => {
  const targets = rules.flatMap((r) => r.targets ?? []);
  return { area_id: [...new Set(targets.flatMap((t) => t.area ?? []))], label_id: [...new Set(targets.flatMap((t) => t.label ?? []))] };
};

export interface ServicePlan {
  grants: number[];
  denies: number[];
  grantSelectors: Selectors;
  denySelectors: Selectors;
  lookup: Allowed;
}

export function planServiceCall(policy: Policy, caller: string, service: string): { plan: ServicePlan } | { plan: undefined; denies: number[] } {
  const grants = indicesOf(
    policy.grants,
    (g) => g.caller === caller && (g.services?.some((p) => matchesServicePattern(p, service, { includeDelegating: false })) ?? false),
  );
  const denies = indicesOf(
    policy.denies,
    (d) => d.caller === caller && d.services.some((p) => matchesServicePattern(p, service, { includeDelegating: true })),
  );
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

export function callable(policy: Policy, caller: string, service: string, targeted: boolean): boolean {
  const { plan } = planServiceCall(policy, caller, service);
  if (!plan) return false;
  return targeted ? plan.grants.some((i) => (policy.grants[i]!.targets?.length ?? 0) > 0) : plan.denies.length === 0;
}

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

type ServiceDecision =
  | { allowed: Allowed & { write: WebSocketWrite }; grants: number[]; denies: []; uncovered: [] }
  | { allowed: undefined; grants: []; denies: number[]; uncovered: string[] };

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

export const writersOf = (policy: Policy, caller: string, kind: ConfigKind) =>
  indicesOf(policy.grants, (g) => g.caller === caller && g.config_write === kind);

export const decideConfigRead = (policy: Policy, caller: string, kind: ConfigKind) =>
  readOf(kind === 'automation' || kind === 'script' ? grantsFor(policy, caller, 'config_read') : writersOf(policy, caller, kind), 'config_read');

const pick = (config: Record<string, unknown>, keys: readonly string[]) => Object.fromEntries(Object.entries(config).filter(([k]) => keys.includes(k)));

export interface ConfigWrite {
  kind: ConfigKind;
  action: 'create' | 'update' | 'delete';
  id: string;
  config?: Record<string, unknown>;
}

function dashboardCommand(action: ConfigWrite['action'], id: string, config: Record<string, unknown>): Command {
  if (action === 'create') return { ...config, type: 'lovelace/dashboards/create', url_path: id };
  if (action === 'update') return { type: 'lovelace/config/save', config, ...dashboardPath(id) };
  return { type: 'lovelace/dashboards/delete', url_path: id };
}

function writeOf({ kind, action, id, config = {} }: ConfigWrite): Write {
  if (kind === 'entity_name') {
    return { via: 'websocket', command: { ...pick(config, ENTITY_NAME_FIELDS), type: 'config/entity_registry/update', entity_id: id } };
  }
  if (kind === 'dashboard') return { via: 'websocket', command: dashboardCommand(action, id, config) };
  const collection = collectionOf(kind, id);
  if (!collection) {
    const request: RestRequest =
      action === 'delete' ? { method: 'DELETE', path: configPath(kind, id) } : { method: 'POST', path: configPath(kind, id), body: config };
    return { via: 'rest', request };
  }
  const [domain, item] = collection;
  if (action === 'create') return { via: 'websocket', command: { ...config, type: `${domain}/create` } };
  return { via: 'websocket', command: { ...(action === 'update' && config), type: `${domain}/${action}`, [`${domain}_id`]: item } };
}

type ConfigWriteDecision = { allowed: Allowed & { write: Write }; grants: number[] } | { allowed: undefined; grants: [] };

const configWriteOf = (grants: number[], write: () => Write): ConfigWriteDecision =>
  grants.length === 0 ? { allowed: undefined, grants: [] } : { allowed: issue({ operation: 'config_write', tier: OPERATION_TIER.config_write, write: write() }), grants };

const isRestConfigKind = (kind: ConfigKind) => kind === 'automation' || kind === 'script' || kind === 'scene';

export function decideConfigWrite(policy: Policy, caller: string, write: ConfigWrite): ConfigWriteDecision {
  if (write.kind === 'helper_entry') return { allowed: undefined, grants: [] };
  if (isRestConfigKind(write.kind) && !isSafeConfigId(write.id)) return { allowed: undefined, grants: [] };
  return configWriteOf(writersOf(policy, caller, write.kind), () => writeOf(write));
}

// HA replaces a whole entry on config/helper/dashboard updates, and helper update schemas reject `id`.
export function mergedUpdate(allowed: Allowed, stored: Record<string, unknown>): Allowed & { write: Write } {
  if (!isIssued(allowed)) throw new Error('only an issued config update merges');
  const { write } = allowed;
  if (write?.via === 'rest' && write.request.method === 'POST') {
    return issue({ ...allowed, write: { via: 'rest', request: { ...write.request, body: { ...stored, ...(write.request.body as object) } } } });
  }
  if (write?.via === 'websocket' && COLLECTION_UPDATE_COMMANDS.has(write.command.type)) {
    const item = Object.fromEntries(Object.entries(stored).filter(([k]) => k !== 'id'));
    return issue({ ...allowed, write: { via: 'websocket', command: { ...item, ...write.command } } });
  }
  if (write?.via === 'websocket' && write.command.type === 'lovelace/config/save') {
    return issue({ ...allowed, write: { via: 'websocket', command: { ...write.command, config: { ...stored, ...(write.command.config as object) } } } });
  }
  throw new Error('only an issued config update merges');
}

// HA deletes dashboards by collection id rather than url_path.
export function dashboardDelete(allowed: Allowed, dashboardId: string): Allowed & { write: Write } {
  const { write } = allowed;
  if (isIssued(allowed) && write?.via === 'websocket' && write.command.type === 'lovelace/dashboards/delete') {
    return issue({ ...allowed, write: { via: 'websocket', command: { type: 'lovelace/dashboards/delete', dashboard_id: dashboardId } } });
  }
  throw new Error('only an issued dashboard delete takes a collection id');
}

export interface BlueprintWrite {
  domain: 'automation' | 'script';
  action: 'create' | 'update' | 'delete';
  path: string;
  yaml?: string;
}

export function decideBlueprintWrite(policy: Policy, caller: string, { domain, action, path, yaml }: BlueprintWrite): ConfigWriteDecision {
  const command =
    action === 'delete'
      ? { type: 'blueprint/delete', domain, path }
      : { type: 'blueprint/save', domain, path, yaml, ...(action === 'update' && { allow_override: true }) };
  return configWriteOf(writersOf(policy, caller, domain), () => ({ via: 'websocket', command }));
}

export type HelperFlow =
  | { action: 'start'; handler: string }
  | { action: 'step'; flow_id: string; input: Record<string, unknown>; options?: boolean }
  | { action: 'abort'; flow_id: string; options?: boolean }
  | { action: 'edit'; entry_id: string }
  | { action: 'delete'; entry_id: string };

function flowRequest(flow: HelperFlow): RestRequest {
  if (flow.action === 'start') return { method: 'POST', path: FLOW_PATH, body: { handler: flow.handler } };
  // HA takes the target entry_id in the `handler` field when opening an options flow.
  if (flow.action === 'edit') return { method: 'POST', path: OPTIONS_PATH, body: { handler: flow.entry_id } };
  if (flow.action === 'delete') return { method: 'DELETE', path: `/api/config/config_entries/entry/${flow.entry_id}` };
  const path = `${flow.options ? OPTIONS_PATH : FLOW_PATH}/${flow.flow_id}`;
  return flow.action === 'step' ? { method: 'POST', path, body: flow.input } : { method: 'DELETE', path };
}

export interface FlowOrigin {
  integration: string;
  discovered?: boolean;
}

export function decideHelperFlow(
  policy: Policy,
  caller: string,
  flow: HelperFlow,
  { integration, discovered }: FlowOrigin,
  helpers: readonly string[],
): ConfigWriteDecision {
  const helper =
    !discovered &&
    helpers.includes(integration) &&
    (flow.action === 'start' ? flow.handler === integration : FLOW_ID.test('entry_id' in flow ? flow.entry_id : flow.flow_id));
  return configWriteOf(helper ? writersOf(policy, caller, 'helper_entry') : [], () => ({ via: 'rest', request: flowRequest(flow) }));
}
