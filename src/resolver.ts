import { isDelegating, TARGET_KEYS } from './evaluator.ts';
import type { Command } from './gate.ts';

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
