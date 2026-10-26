import { ProtocolError, ProtocolErrorCode, Server, type CallToolResult, type Tool } from '@modelcontextprotocol/server';
import * as z from 'zod';
import pkg from '../package.json' with { type: 'json' };
import type { Authenticated } from './auth.ts';
import { decideRead, grantsFor, type Allowed, type Operation } from './evaluator.ts';
import { HaUnavailable, type Command, type Gate } from './gate.ts';
import type { Audit } from './log.ts';
import type { Policy } from './policy.ts';
import { stripBearerTokens } from './redaction.ts';

/** The Operation kind a Caller must hold to see and call each tool. */
export const TOOL_KIND = {
  ha_get_states: 'plain_read',
  ha_get_history: 'plain_read',
  ha_get_logbook: 'plain_read',
  ha_get_registry: 'plain_read',
} as const satisfies Record<string, Operation>;
export type ToolName = keyof typeof TOOL_KIND;

const OPERATION_NAME: Record<Operation, string> = {
  plain_read: 'plain read',
  config_read: 'config read',
  service_call: 'service calls',
  config_write: 'config writes',
};

interface Context {
  policy: Policy;
  caller: Authenticated;
  gate: Gate;
}

interface ToolSpec<Input extends z.ZodType> {
  title: string;
  description: string;
  input: Input;
  annotations: { readOnlyHint: boolean; destructiveHint: boolean };
  run(args: z.output<Input>, ctx: Context): Promise<CallToolResult>;
}

const page = {
  limit: z.number().int().min(1).max(500).default(50).describe('Page size, at most 500.'),
  offset: z.number().int().min(0).default(0).describe('Entries to skip.'),
};
type Page = { limit: number; offset: number };
const pageOf = (key: string, items: unknown[], { limit, offset }: Page) => ({
  total: items.length,
  offset,
  has_more: offset + limit < items.length,
  [key]: items.slice(offset, offset + limit),
});

const entityId = z.string().regex(/^[a-z0-9_]+\.[a-z0-9_]+$/, 'must be an entity_id such as light.kitchen');
const window = {
  start: z.iso.datetime({ offset: true }).optional().describe('ISO 8601 start time.'),
  end: z.iso.datetime({ offset: true }).optional().describe('ISO 8601 end time; defaults to now.'),
};
/** Fills a window left open: `end` defaults to now and `start` to `hours` before `end`. */
function windowOf(args: { start?: string; end?: string }, hours: number) {
  const end = args.end ?? new Date().toISOString();
  return { start: args.start ?? new Date(Date.parse(end) - hours * 3_600_000).toISOString(), end };
}
/** HA sends times as float seconds. */
const isoOf = (seconds: number) => new Date(Math.round(seconds * 1000)).toISOString();

/** About 80 kB keeps a result under Claude Code's default MCP output limit. */
const BYTE_CAP = 80_000;
const READS: ReadonlySet<Operation> = new Set(['plain_read', 'config_read']);

const text = (value: unknown): CallToolResult => ({ content: [{ type: 'text', text: JSON.stringify(value) }] });
const failure = (message: string): CallToolResult => ({ isError: true, content: [{ type: 'text', text: message }] });

/** A failure the Caller can act on, returned as an isError result. */
class ToolFailure extends Error {}

/** Sends a read the evaluator allowed. */
async function read<T>(ctx: Context, allowed: Allowed | undefined, command: Command): Promise<T> {
  if (!allowed) throw new Error('read sent without an Allowed');
  try {
    return stripBearerTokens(await ctx.gate.send(allowed, command)) as T;
  } catch (e) {
    if (e instanceof HaUnavailable) throw new ToolFailure('HA unavailable: nothing was sent to Home Assistant. Try again later.');
    throw e;
  }
}

/** Sends a plain read, which the evaluator decides by the Caller alone. */
const plainRead = <T>(ctx: Context, command: Command) =>
  read<T>(ctx, decideRead(ctx.policy, ctx.caller.caller, 'plain_read').allowed, command);

interface HaState {
  entity_id: string;
  state: string;
  attributes: { friendly_name?: string };
}

interface RegistryEntity {
  entity_id: string;
  device_id: string | null;
  area_id: string | null;
  labels: string[];
}

/** Each registered entity's aliases and its area and label names, which a states query also matches. */
async function registryNames(ctx: Context): Promise<Map<string, string[]>> {
  const [entities, devices, areas, labels] = await Promise.all([
    plainRead<RegistryEntity[]>(ctx, { type: 'config/entity_registry/list' }),
    plainRead<{ id: string; area_id: string | null }[]>(ctx, { type: 'config/device_registry/list' }),
    plainRead<{ area_id: string; name: string }[]>(ctx, { type: 'config/area_registry/list' }),
    plainRead<{ label_id: string; name: string }[]>(ctx, { type: 'config/label_registry/list' }),
  ]);
  // Only the extended entries carry aliases.
  const extended = await plainRead<Record<string, { aliases?: (string | null)[] } | null>>(ctx, {
    type: 'config/entity_registry/get_entries',
    entity_ids: entities.map((e) => e.entity_id),
  });
  const areaName = new Map(areas.map((a) => [a.area_id, a.name]));
  const labelName = new Map(labels.map((l) => [l.label_id, l.name]));
  const deviceArea = new Map(devices.map((d) => [d.id, d.area_id]));
  return new Map(
    entities.map((e) => {
      const area = e.area_id ?? deviceArea.get(e.device_id ?? '') ?? '';
      const names = [...(extended[e.entity_id]?.aliases ?? []), areaName.get(area), ...e.labels.map((l) => labelName.get(l))];
      return [e.entity_id, names.filter((n): n is string => typeof n === 'string')];
    }),
  );
}

/** Infers each tool's arguments from its input schema, then erases them for the shared table. */
const defineTool = <Input extends z.ZodType>(spec: ToolSpec<Input>) => spec as unknown as ToolSpec<z.ZodType>;

const getStates = defineTool({
  title: 'Get entity states',
  description: [
    'Lists the current state of Home Assistant entities, sorted by entity_id, with each entity_id, friendly name and state.',
    'Filter by `domain` (such as `light`), by exact `state` (such as `on`), and by `query`, a case-insensitive substring of the entity_id, friendly name, aliases, or area and label names.',
    'Attributes are left out unless `full` is true; bearer tokens in camera, image and media_player attributes are always removed.',
    'Results come in pages: `limit` (default 50, at most 500) and `offset` pick the page, and the response gives `total` and `has_more`.',
    'Example: {"domain": "light", "query": "kitchen", "state": "on"} lists the kitchen lights that are on.',
  ].join(' '),
  input: z.strictObject({
    query: z.string().min(1).optional().describe('Case-insensitive substring of the entity_id, friendly name, aliases, or area and label names.'),
    domain: z.string().regex(/^[a-z0-9_]+$/).optional().describe('Entity domain, such as light or sensor.'),
    state: z.string().min(1).optional().describe('Exact state, such as on or unavailable.'),
    full: z.boolean().default(false).describe('Include every attribute.'),
    ...page,
  }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run(args, ctx) {
    const states = await plainRead<HaState[]>(ctx, { type: 'get_states' });
    const query = args.query?.toLowerCase();
    const names = query === undefined ? new Map<string, string[]>() : await registryNames(ctx);
    const matches = states
      .filter((s) => args.domain === undefined || s.entity_id.startsWith(`${args.domain}.`))
      .filter((s) => args.state === undefined || s.state === args.state)
      .filter(
        (s) =>
          query === undefined ||
          [s.entity_id, s.attributes.friendly_name ?? '', ...(names.get(s.entity_id) ?? [])].some((v) => v.toLowerCase().includes(query)),
      )
      .sort((a, b) => a.entity_id.localeCompare(b.entity_id));
    const shown = matches.map((s) => ({
      entity_id: s.entity_id,
      name: s.attributes.friendly_name,
      state: s.state,
      ...(args.full && { attributes: s.attributes }),
    }));
    return text(pageOf('states', shown, args));
  },
});

/** One entity's changes in a window: numeric states get min, max and mean, others a count per state. */
function summarise(entity_id: string, states: string[]) {
  const summary = { entity_id, changes: states.length, first: states[0], last: states.at(-1) };
  const numbers = states.filter((s) => s.trim() !== '').map(Number).filter(Number.isFinite);
  if (numbers.length > 0) {
    const sum = numbers.reduce((a, b) => a + b, 0);
    return { ...summary, min: numbers.reduce((a, b) => Math.min(a, b)), max: numbers.reduce((a, b) => Math.max(a, b)), mean: sum / numbers.length };
  }
  const counts: Record<string, number> = {};
  for (const s of states) counts[s] = (counts[s] ?? 0) + 1;
  return { ...summary, states: counts };
}

const getHistory = defineTool({
  title: 'Get entity history',
  description: [
    'Lists the state changes of the given entities over a time window, one row per change with its entity_id, state and last_changed time, sorted by entity_id and then time.',
    'The window defaults to the last 24 hours; `start` and `end` take ISO 8601 times.',
    'With `summary` it returns one entry per entity instead: the number of changes, the first and last state, and either the minimum, maximum and mean of numeric states or a count of each state.',
    'Attributes are not returned. Results come in pages: `limit` (default 50, at most 500) and `offset` pick the page, and the response gives `total` and `has_more`.',
    'Example: {"entity_ids": ["sensor.kitchen_temperature"], "summary": true} summarises the kitchen temperature over the last day.',
  ].join(' '),
  input: z.strictObject({
    entity_ids: z.array(entityId).min(1).describe('The entities to read, such as ["light.kitchen"].'),
    ...window,
    summary: z.boolean().default(false).describe('One summary entry per entity instead of every change.'),
    ...page,
  }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run(args, ctx) {
    const { start, end } = windowOf(args, 24);
    const changes = await plainRead<Record<string, { s: string; lu: number; lc?: number }[]>>(ctx, {
      type: 'history/history_during_period',
      start_time: start,
      end_time: end,
      entity_ids: args.entity_ids,
      no_attributes: true,
    });
    const ids = Object.keys(changes).sort();
    const entries = args.summary
      ? ids.map((id) => summarise(id, changes[id]!.map((c) => c.s)))
      : ids.flatMap((id) => changes[id]!.map((c) => ({ entity_id: id, state: c.s, last_changed: isoOf(c.lc ?? c.lu) })));
    return text({ start, end, ...pageOf('history', entries, args) });
  },
});

const getLogbook = defineTool({
  title: 'Get logbook',
  description: [
    'Lists Home Assistant logbook entries over a time window, oldest first: what changed or happened, when, and the context that caused it.',
    'The window defaults to the last hour; `start` and `end` take ISO 8601 times, and `entity_id` keeps only one entity\'s entries.',
    'Results come in pages: `limit` (default 50, at most 500) and `offset` pick the page, and the response gives `total` and `has_more`.',
    'Example: {"entity_id": "lock.front_door", "start": "2026-10-26T06:00:00Z"} shows the front door lock since 6 am UTC.',
  ].join(' '),
  input: z.strictObject({
    ...window,
    entity_id: entityId.optional().describe('Only this entity\'s entries.'),
    ...page,
  }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run(args, ctx) {
    const { start, end } = windowOf(args, 1);
    const entries = await plainRead<{ when: number }[]>(ctx, {
      type: 'logbook/get_events',
      start_time: start,
      end_time: end,
      ...(args.entity_id !== undefined && { entity_ids: [args.entity_id] }),
    });
    return text({ start, end, ...pageOf('entries', entries.map((e) => ({ ...e, when: isoOf(e.when) })), args) });
  },
});

/** Whether any text field of a registry entry, or any text in a list field, contains `query`. */
const mentions = (entry: Record<string, unknown>, query: string) =>
  Object.values(entry).some((v) => [v].flat().some((x) => typeof x === 'string' && x.toLowerCase().includes(query)));

const getRegistry = defineTool({
  title: 'Get registry',
  description: [
    'Lists the entries of one Home Assistant registry, in registry order: `entity`, `device`, `area`, `label` or `floor`.',
    'Entries are returned as Home Assistant stores them, with ids, names and the area, floor, device and label ids that link them.',
    '`query` keeps entries whose text fields contain it, case-insensitively, such as an id, a name or an alias.',
    'Results come in pages: `limit` (default 50, at most 500) and `offset` pick the page, and the response gives `total` and `has_more`.',
    'Example: {"registry": "area", "query": "kitchen"} finds the kitchen area and its floor_id.',
  ].join(' '),
  input: z.strictObject({
    registry: z.enum(['entity', 'device', 'area', 'label', 'floor']).describe('The registry to list.'),
    query: z.string().min(1).optional().describe('Case-insensitive substring of any text field.'),
    ...page,
  }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run(args, ctx) {
    const entries = await plainRead<Record<string, unknown>[]>(ctx, { type: `config/${args.registry}_registry/list` });
    const query = args.query?.toLowerCase();
    return text(pageOf('entries', query === undefined ? entries : entries.filter((e) => mentions(e, query)), args));
  },
});

const TOOLS: Record<ToolName, ToolSpec<z.ZodType>> = {
  ha_get_states: getStates,
  ha_get_history: getHistory,
  ha_get_logbook: getLogbook,
  ha_get_registry: getRegistry,
};

/** Built once, so each tool's definition is identical for every Caller. */
const DEFINITIONS = Object.fromEntries(
  Object.entries(TOOLS).map(([name, t]) => [
    name,
    { name, title: t.title, description: t.description, inputSchema: z.toJSONSchema(t.input, { io: 'input' }), annotations: t.annotations } as Tool,
  ]),
) as Record<ToolName, Tool>;

const isTool = (name: string): name is ToolName => Object.hasOwn(TOOLS, name);

/** Cross-tool workflow, one line per tool that has any, so instructions depend only on the visible tools. */
const TOOL_INSTRUCTIONS: Partial<Record<ToolName, string>> = {
  ha_get_states: 'Find entities and their entity_ids with ha_get_states, using its filters, before reading history or the logbook.',
};
const GENERAL_INSTRUCTIONS = [
  'Every call is checked against the Grants this Caller holds. A denied call means there is no Grant for it, so do not retry it or try to reach the same result another way.',
  'Lists return `total` and `has_more`: while `has_more` is true, call again with `offset` raised by `limit`. A response that is too large is refused rather than cut off, so narrow the query and call again.',
];
const instructionsFor = (visible: ToolName[]) => [...visible.flatMap((name) => TOOL_INSTRUCTIONS[name] ?? []), ...GENERAL_INSTRUCTIONS].join('\n');

/**
 * One server per request, listing only the tools whose kind the Caller holds. A hidden tool called
 * directly is refused and audited before its input is read, so nothing reaches HA.
 */
/** Allowed Operations are audited only on the deployer's opt-in, so reads don't drown the log. */
export interface AuditOptions {
  auditReads: boolean;
}

export function buildServer(policy: Policy, gate: Gate, audit: Audit, caller: Authenticated, options: AuditOptions): Server {
  const ctx: Context = { policy, caller, gate };
  const holds = (name: ToolName) => grantsFor(policy, caller.caller, TOOL_KIND[name]).length > 0;
  const visible = (Object.keys(TOOLS) as ToolName[]).filter(holds);
  const server = new Server(
    { name: pkg.name, version: pkg.version },
    {
      capabilities: { tools: {} },
      instructions: instructionsFor(visible),
      cacheHints: { 'tools/list': { cacheScope: 'private', ttlMs: 0 } },
    },
  );
  server.setRequestHandler('tools/list', () => ({ tools: visible.map((name) => DEFINITIONS[name]) }));
  server.setRequestHandler('tools/call', async ({ params }) => {
    const { name } = params;
    if (!isTool(name)) throw new ProtocolError(ProtocolErrorCode.InvalidParams, `Tool ${name} not found`);
    const operation = TOOL_KIND[name];
    const who = { caller: caller.caller, key_hash_prefix: caller.keyHashPrefix, operation, tool: name };
    if (!holds(name)) {
      audit({ ...who, decision: 'deny', grants: [] });
      return failure(`Denied: this Caller holds no Grant for ${OPERATION_NAME[operation]}. Do not retry this call.`);
    }
    const tool = TOOLS[name];
    const args = tool.input.safeParse(params.arguments ?? {});
    if (!args.success) {
      return failure(`Input validation error: ${args.error.issues.map((i) => `${i.path.join('.') || '(arguments)'}: ${i.message}`).join('; ')}`);
    }
    if (options.auditReads && READS.has(operation)) {
      audit({ ...who, decision: 'allow', grants: grantsFor(policy, caller.caller, operation), request: args.data });
    }
    try {
      const result = await tool.run(args.data, ctx);
      // A read is refused whole rather than cut off, so the Caller never reasons over a truncated answer.
      if (READS.has(operation) && Buffer.byteLength(JSON.stringify(result.content)) > BYTE_CAP) {
        return failure(`The response is over ${BYTE_CAP / 1000} kB, so nothing was returned: narrow the query with filters, a shorter window or a smaller limit.`);
      }
      return server.projectCallToolResult(result, undefined);
    } catch (e) {
      if (e instanceof ToolFailure) return failure(e.message);
      throw e;
    }
  });
  return server;
}
