import { isDelegating, TARGET_KEYS } from './evaluator.ts';
import type { Command } from './gate.ts';
import type { Policy } from './policy.ts';

/** HA's target forms, each key normalised to a list. */
export type Target = Partial<Record<(typeof TARGET_KEYS)[number], string[]>>;
type Send = (command: Command) => Promise<unknown>;

const listOf = (value: unknown): string[] => (value === undefined ? [] : (Array.isArray(value) ? value : [value]).map(String));

/** Target keys in service data join the target, as HA merges them, so data cannot carry an unchecked target. */
export function mergeTarget(target: Record<string, unknown> = {}, data: Record<string, unknown> = {}): Target {
  const merged: Target = {};
  for (const key of TARGET_KEYS) {
    const values = [...new Set([...listOf(target[key]), ...listOf(data[key])])].filter((v) => v !== 'none');
    if (values.length > 0) merged[key] = values;
  }
  return merged;
}

/**
 * The domains a service's declared `target.entity` filter admits, or undefined when it admits any (ADR 0008 amendment).
 * HA acts only on these, so the resolver leaves the rest of an expansion out; a filter entry without a domain admits any.
 */
export function domainsOf(target: unknown): Set<string> | undefined {
  const entity = (target as { entity?: unknown } | null | undefined)?.entity;
  const filters = (entity === undefined || entity === null ? [] : Array.isArray(entity) ? entity : [entity]) as { domain?: unknown }[];
  if (filters.length === 0 || filters.some((f) => f?.domain === undefined)) return undefined;
  return new Set(filters.flatMap((f) => listOf(f.domain)));
}

/** `entity_id: all` becomes the entities of the service's domain, or every entity for a delegating service. */
export async function expandAll(send: Send, target: Target, service: string): Promise<Target> {
  if (!target.entity_id?.includes('all')) return target;
  const states = (await send({ type: 'get_states' })) as { entity_id: string }[];
  const domain = `${service.split('.')[0]}.`;
  const all = states.map((s) => s.entity_id).filter((e) => isDelegating(service) || e.startsWith(domain));
  return { ...target, entity_id: [...target.entity_id.filter((e) => e !== 'all'), ...all] };
}

/** HA's own expansion of a target, asked live; an empty target expands to nothing without asking. */
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

/**
 * Every area, label, domain and service the Policy names that HA does not know, as `<path>: <problem>`.
 * `check` refuses these and startup warns. A target domain is known if HA offers a service or holds an entity in it.
 */
export async function unknownNames(policy: Policy, send: Send): Promise<string[]> {
  const rules = [...policy.grants.map((r, i) => [`grants.${i}`, r] as const), ...policy.denies.map((r, i) => [`denies.${i}`, r] as const)];
  const targets = rules.flatMap(([, r]) => r.targets ?? []);
  const areas = [...new Set(targets.flatMap((t) => t.area ?? []))];
  const labels = [...new Set(targets.flatMap((t) => t.label ?? []))];
  const services = (await send({ type: 'get_services' })) as Record<string, Record<string, unknown>>;
  const domains = new Set(Object.keys(services));
  if (targets.some((t) => t.domain !== undefined && t.domain !== '*' && !domains.has(t.domain))) {
    for (const { entity_id } of (await send({ type: 'get_states' })) as { entity_id: string }[]) domains.add(entity_id.split('.')[0]!);
  }
  type Missing = Record<'missing_areas' | 'missing_labels', string[]>;
  const missing: Missing =
    areas.length + labels.length === 0
      ? { missing_areas: [], missing_labels: [] }
      : ((await send({ type: 'extract_from_target', target: { area_id: areas, label_id: labels }, expand_group: false })) as Missing);

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
