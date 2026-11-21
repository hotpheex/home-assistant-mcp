import { isDelegating, selectorsOf, type Expansion, type ServicePlan } from './evaluator.ts';
import { TARGET_KEYS, type Command } from './ha.ts';
import type { Policy } from './policy.ts';

export type Target = Partial<Record<(typeof TARGET_KEYS)[number], string[]>>;
type Send = (command: Command) => Promise<unknown>;

const listOf = (value: unknown): string[] => (value === undefined ? [] : (Array.isArray(value) ? value : [value]).map(String));

export function mergeTarget(target: Record<string, unknown> = {}, data: Record<string, unknown> = {}): Target {
  const merged: Target = {};
  for (const key of TARGET_KEYS) {
    const values = [...new Set([...listOf(target[key]), ...listOf(data[key])])].filter((v) => v !== 'none');
    if (values.length > 0) merged[key] = values;
  }
  return merged;
}

function domainsOf(target: unknown): Set<string> | undefined {
  const entity = (target as { entity?: unknown } | null | undefined)?.entity;
  const filters = (entity === undefined || entity === null ? [] : Array.isArray(entity) ? entity : [entity]) as { domain?: unknown }[];
  if (filters.length === 0 || filters.some((f) => f?.domain === undefined)) return undefined;
  return new Set(filters.flatMap((f) => listOf(f.domain)));
}

async function expandAll(send: Send, target: Target, service: string): Promise<Target> {
  if (!target.entity_id?.includes('all')) return target;
  const states = (await send({ type: 'get_states' })) as { entity_id: string }[];
  const domain = `${service.split('.')[0]}.`;
  const all = states.map((s) => s.entity_id).filter((e) => isDelegating(service) || e.startsWith(domain));
  return { ...target, entity_id: [...target.entity_id.filter((e) => e !== 'all'), ...all] };
}

export async function extract(send: Send, target: Target, primaryEntitiesOnly = true): Promise<string[]> {
  const keys = Object.fromEntries(Object.entries(target).filter(([, v]) => v.length > 0));
  if (Object.keys(keys).length === 0) return [];
  const result = (await send({
    type: 'extract_from_target',
    target: keys,
    expand_group: false,
    ...(primaryEntitiesOnly ? {} : { primary_entities_only: false }),
  })) as { referenced_entities: string[] };
  return [...result.referenced_entities].sort();
}

export type TargetResolution =
  | { ok: true; expansion: Expansion }
  | { ok: false; reason: string; message: string; entities?: string[] };

export async function resolveCallTarget(
  send: Send,
  plan: ServicePlan,
  requested: Target,
  targetSchema: unknown,
  serviceName: string,
): Promise<TargetResolution> {
  const targeted = targetSchema !== undefined;
  const hasTarget = Object.keys(requested).length > 0;
  if (targeted && !hasTarget) return { ok: false, reason: 'this service needs a target', message: `${serviceName}: this service needs a target.` };
  if (!targeted && hasTarget) return { ok: false, reason: 'this service takes no target', message: `${serviceName}: this service takes no target.` };
  if (!targeted) return { ok: true, expansion: { targeted: false, entities: [], grantEntities: [], denyEntities: [] } };

  const reached = await extract(send, await expandAll(send, requested, serviceName));
  const domains = domainsOf(targetSchema);
  const admitted = (e: string) => domains?.has(e.split('.')[0]!) ?? true;
  const namedOutside = (requested.entity_id ?? []).filter((e) => e !== 'all' && !admitted(e));
  if (namedOutside.length > 0) {
    return {
      ok: false,
      reason: 'entity outside the service domains',
      message: `${serviceName} acts only on ${[...domains!].join(', ')} entities; remove ${namedOutside.join(', ')} from the target.`,
      entities: namedOutside,
    };
  }
  const entities = reached.filter(admitted);
  if (entities.length === 0) return { ok: false, reason: 'target matches no entity', message: `${serviceName}: target matches no entity.` };

  const grantEntities = await extract(send, plan.grantSelectors);
  const denyEntities = await extract(send, plan.denySelectors, false);
  return { ok: true, expansion: { targeted: true, entities, grantEntities, denyEntities } };
}

export async function unknownNames(policy: Policy, send: Send): Promise<string[]> {
  const rules = [...policy.grants.map((r, i) => [`grants.${i}`, r] as const), ...policy.denies.map((r, i) => [`denies.${i}`, r] as const)];
  if (!rules.some(([, r]) => r.services)) return [];
  const targets = rules.flatMap(([, r]) => r.targets ?? []);
  const selectors = selectorsOf(rules.map(([, r]) => r));
  const services = (await send({ type: 'get_services' })) as Record<string, Record<string, unknown>>;
  const domains = new Set(Object.keys(services));
  if (targets.some((t) => t.domain !== undefined && t.domain !== '*' && !domains.has(t.domain))) {
    for (const { entity_id } of (await send({ type: 'get_states' })) as { entity_id: string }[]) domains.add(entity_id.split('.')[0]!);
  }
  type Missing = Record<'missing_areas' | 'missing_labels', string[]>;
  const missing: Missing =
    selectors.area_id.length + selectors.label_id.length === 0
      ? { missing_areas: [], missing_labels: [] }
      : ((await send({ type: 'extract_from_target', target: selectors, expand_group: false })) as Missing);

  return rules.flatMap(([path, rule]) => [
    ...(rule.services ?? []).flatMap((s, j) => {
      const [domain, name] = s.split('.') as [string, string];
      if (name === '*') return services[domain] ? [] : [`${path}.services.${j}: Home Assistant has no domain "${domain}"`];
      return services[domain]?.[name] ? [] : [`${path}.services.${j}: Home Assistant has no service "${s}"`];
    }),
    ...(rule.targets ?? []).flatMap((t, j) => {
      const at = `${path}.targets.${j}`;
      if (t.area !== undefined) return missing.missing_areas.includes(t.area) ? [`${at}.area: Home Assistant has no area "${t.area}"`] : [];
      if (t.label !== undefined) return missing.missing_labels.includes(t.label) ? [`${at}.label: Home Assistant has no label "${t.label}"`] : [];
      return t.domain === '*' || domains.has(t.domain!) ? [] : [`${at}.domain: Home Assistant has no domain "${t.domain}"`];
    }),
  ]);
}
