import { ProtocolError, ProtocolErrorCode, Server, type CallToolResult, type Tool } from '@modelcontextprotocol/server';
import * as z from 'zod';
import pkg from '../package.json' with { type: 'json' };
import type { Authenticated } from './auth.ts';
import {
  callable,
  configPath,
  decideConfigRead,
  decideConfigWrite,
  decideRead,
  decideServiceCall,
  grantsFor,
  HELPER_DOMAINS,
  mergedUpdate,
  planServiceCall,
  splitHelperId,
  type Allowed,
  type ConfigWrite,
  type Operation,
} from './evaluator.ts';
import { HaUnavailable, OutcomeUnknown, type Command, type Gate, type RestRequest } from './gate.ts';
import { auditFor, type Audit } from './log.ts';
import { CONFIG_KINDS, type Policy } from './policy.ts';
import { maskSecrets, redactedPath, stripBearerTokens } from './redaction.ts';
import { domainsOf, expandAll, extract, mergeTarget } from './resolver.ts';

/** The Operation kind a Caller must hold to see and call each tool. */
export const TOOL_KIND = {
  ha_get_states: 'plain_read',
  ha_get_history: 'plain_read',
  ha_get_logbook: 'plain_read',
  ha_get_registry: 'plain_read',
  ha_list_services: 'plain_read',
  ha_get_config: 'config_read',
  ha_list_traces: 'config_read',
  ha_get_trace: 'config_read',
  ha_write_config: 'config_write',
  ha_call_service: 'service_call',
} as const satisfies Record<string, Operation>;
export type ToolName = keyof typeof TOOL_KIND;

const OPERATION_NAME: Record<Operation, string> = {
  plain_read: 'plain read',
  config_read: 'config read',
  service_call: 'service calls',
  config_write: 'config writes',
};

/** The allowing Grants, what a denial names, and the names to audit. */
interface Decided {
  grants: number[];
  lacking: string;
  request: Record<string, unknown>;
  /** What `run` sends, so it sends what was checked rather than deciding again; a service call decides per target in `run`. */
  allowed?: Allowed;
}

interface Context extends Decided {
  policy: Policy;
  auth: Authenticated;
  gate: Gate;
  audit: Audit;
  options: AuditOptions;
}

interface ToolSpec<Input extends z.ZodType> {
  title: string;
  description: string;
  input: Input;
  annotations: { readOnlyHint: boolean; destructiveHint: boolean };
  /** For a decision that needs the arguments, not just the tool's kind. */
  decide?(args: z.output<Input>, policy: Policy, caller: string): Decided;
  run(args: z.output<Input>, ctx: Context): Promise<CallToolResult>;
}

const PAGED = 'Results come in pages: `limit` (default 50, at most 500) and `offset` pick the page, and the response gives `total` and `has_more`.';
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

const slug = z.string().regex(/^[a-z0-9_]+$/);
const entityId = z.string().regex(/^[a-z0-9_]+\.[a-z0-9_]+$/, 'must be an entity_id such as light.kitchen');
const window = {
  start: z.iso.datetime({ offset: true }).optional().describe('ISO 8601 start time.'),
  end: z.iso.datetime({ offset: true }).optional().describe('ISO 8601 end time; defaults to now.'),
};
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

/** The gate's outage errors as failures the Caller can act on; anything else unchanged. */
function outage(e: unknown): unknown {
  if (e instanceof HaUnavailable) {
    return new ToolFailure(e.sent ? 'HA unavailable: Home Assistant did not answer. Try again later.' : 'HA unavailable: nothing was sent to Home Assistant. Try again later.');
  }
  if (e instanceof OutcomeUnknown) {
    return new ToolFailure('Outcome unknown: the connection to Home Assistant dropped after the call was sent. Check state before retrying.');
  }
  return e;
}

/** Sends over WebSocket; HA's refusals and outages become failures the Caller can act on. */
async function send<T>(ctx: Context, allowed: Allowed | undefined, command: Command): Promise<T> {
  if (!allowed) throw new Error('sent without an Allowed');
  try {
    return stripBearerTokens(await ctx.gate.send(allowed, command)) as T;
  } catch (e) {
    const refusal = e as { code?: unknown; message?: unknown } | null;
    // HA's error results arrive as plain {code, message} objects, never as Errors.
    if (!(e instanceof Error) && typeof refusal?.code === 'string' && typeof refusal.message === 'string') {
      throw new ToolFailure(`Home Assistant refused the request: ${refusal.message}`);
    }
    throw outage(e);
  }
}

/** A write has already run, so an oversize response is cut with a visible marker rather than refused. */
function writeResult(value: unknown): CallToolResult {
  const full = Buffer.from(JSON.stringify(value));
  if (full.length <= BYTE_CAP) return text(value);
  const marker = `\n[truncated: the response was ${full.length} bytes, over the ${BYTE_CAP}-byte cap; the call ran]`;
  const kept = full.subarray(0, BYTE_CAP - Buffer.byteLength(marker)).toString().replace(/\uFFFD$/, '');
  return { content: [{ type: 'text', text: kept + marker }] };
}

/** Every read masks secrets, so Redaction means one thing on every read; a write's lookup uses `send`, unmasked, to merge. */
const plainRead = async <T>(ctx: Context, command: Command) => maskSecrets(await send(ctx, ctx.allowed, command)) as T;
const configRead = plainRead;

/** Sends a config REST request; HA's error statuses become failures, except a 404 on GET, which means no such item. */
async function rest(ctx: Context, allowed: Allowed | undefined, request: RestRequest): Promise<unknown> {
  if (!allowed) throw new Error('REST sent without an Allowed');
  const answer = await ctx.gate.rest(allowed, request).catch((e: unknown) => {
    throw outage(e);
  });
  if (answer.status === 404 && request.method === 'GET') return undefined;
  if (answer.status !== 200) {
    const message = (answer.body as { message?: string } | null)?.message ?? `HTTP ${answer.status}`;
    throw new ToolFailure(`Home Assistant refused the request: ${message}`);
  }
  return answer.body;
}

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
    'Filter by `area` or `label` id to get what a Home Assistant service call targeting that area or label acts on.',
    'Attributes are left out unless `full` is true; bearer tokens in camera, image and media_player attributes are always removed, and secret-looking values come back as **REDACTED**, best-effort.',
    PAGED,
    'Example: {"domain": "light", "query": "kitchen", "state": "on"} lists the kitchen lights that are on.',
  ].join(' '),
  input: z.strictObject({
    query: z.string().min(1).optional().describe('Case-insensitive substring of the entity_id, friendly name, aliases, or area and label names.'),
    domain: slug.optional().describe('Entity domain, such as light or sensor.'),
    state: z.string().min(1).optional().describe('Exact state, such as on or unavailable.'),
    area: z.string().min(1).optional().describe('Area id, such as living_room.'),
    label: z.string().min(1).optional().describe('Label id.'),
    full: z.boolean().default(false).describe('Include every attribute.'),
    ...page,
  }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run(args, ctx) {
    const states = await plainRead<HaState[]>(ctx, { type: 'get_states' });
    const query = args.query?.toLowerCase();
    const names = query === undefined ? new Map<string, string[]>() : await registryNames(ctx);
    const within = async (key: 'area_id' | 'label_id', id: string | undefined) =>
      id === undefined ? undefined : new Set(await extract((command) => plainRead(ctx, command), { [key]: [id] }));
    const inArea = await within('area_id', args.area);
    const labelled = await within('label_id', args.label);
    const matches = states
      .filter((s) => args.domain === undefined || s.entity_id.startsWith(`${args.domain}.`))
      .filter((s) => (inArea?.has(s.entity_id) ?? true) && (labelled?.has(s.entity_id) ?? true))
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
    'Attributes are not returned.',
    PAGED,
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
    PAGED,
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

const mentions = (entry: Record<string, unknown>, query: string) =>
  Object.values(entry).some((v) => [v].flat().some((x) => typeof x === 'string' && x.toLowerCase().includes(query)));

const getRegistry = defineTool({
  title: 'Get registry',
  description: [
    'Lists the entries of one Home Assistant registry, in registry order: `entity`, `device`, `area`, `label` or `floor`.',
    'Entries are returned as Home Assistant stores them, with ids, names and the area, floor, device and label ids that link them.',
    '`query` keeps entries whose text fields contain it, case-insensitively, such as an id, a name or an alias.',
    PAGED,
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

const scriptKind = z.enum(['automation', 'script']);
const itemId = z.string().min(1).describe("The automation's config `id`, or the script's object id (the part after `script.`).");

const configKind = z.enum(CONFIG_KINDS);
const helperId = new RegExp(`^(${HELPER_DOMAINS.join('|')})\\.[a-z0-9_]+$`);
const HELPER_ID_RULE = 'must be <helper domain>.<id>, such as input_boolean.guest_mode';

const getConfig = defineTool({
  title: 'Get config',
  description: [
    'Returns the stored configuration of one automation, script, scene or helper (input_*, counter, timer or schedule).',
    'Name an automation or script by `kind` and `entity_id`, such as automation.porch_light; a scene by its config `id`; and a helper by `id` as `<domain>.<id>`, such as input_boolean.guest_mode.',
    'Scene and helper configs are served only to a Caller that may write that kind.',
    'Values that look like secrets, such as passwords, tokens, API keys, URL credentials and Bearer tokens, come back as **REDACTED**; this is best-effort, so other secrets in the config may still show.',
    'Example: {"kind": "automation", "entity_id": "automation.porch_light"}.',
  ].join(' '),
  input: z
    .strictObject({
      kind: configKind.describe('automation, script, scene or helper.'),
      entity_id: entityId.optional().describe('For an automation or script: its entity, such as automation.porch_light.'),
      id: z.string().min(1).optional().describe('For a scene: its config id. For a helper: <domain>.<id>, such as input_boolean.guest_mode.'),
    })
    .superRefine(({ kind, entity_id, id }, ctx) => {
      const byEntity = kind === 'automation' || kind === 'script';
      if (byEntity && entity_id === undefined) ctx.addIssue({ code: 'custom', path: ['entity_id'], message: `is required for an ${kind}` });
      if (!byEntity && id === undefined) ctx.addIssue({ code: 'custom', path: ['id'], message: `is required for a ${kind}` });
      if (kind === 'helper' && id !== undefined && !helperId.test(id)) ctx.addIssue({ code: 'custom', path: ['id'], message: HELPER_ID_RULE });
    }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  decide: ({ kind }, policy, caller) => ({ ...decideConfigRead(policy, caller, kind), lacking: `${kind} config`, request: { kind } }),
  async run({ kind, entity_id, id }, ctx) {
    if (kind === 'automation' || kind === 'script') return text(await configRead(ctx, { type: `${kind}/config`, entity_id }));
    if (kind === 'scene') {
      const config = await rest(ctx, ctx.allowed, { method: 'GET', path: configPath(kind, id!) });
      if (config === undefined) throw new ToolFailure(`Scene ${id} not found.`);
      return text({ config: maskSecrets(stripBearerTokens(config)) });
    }
    const [domain, item] = splitHelperId(id!);
    const config = (await configRead<{ id: string }[]>(ctx, { type: `${domain}/list` })).find((h) => h.id === item);
    if (config === undefined) throw new ToolFailure(`Helper ${id} not found.`);
    return text({ config });
  },
});

type TraceSummary = { timestamp: { start: string } };

const listTraces = defineTool({
  title: 'List traces',
  description: [
    'Lists the stored runs of one automation or script, newest first, as summaries: run_id, start and finish time, state, last step, what triggered it and any error.',
    'Name the item by `kind` (automation or script) and `id`: an automation\'s config `id` from its config, or a script\'s object id, the part of its entity_id after `script.`.',
    'Secret-looking values come back as **REDACTED**, best-effort.',
    PAGED,
    'Example: {"kind": "script", "id": "morning"} lists the runs of script.morning.',
  ].join(' '),
  // HA's trace/list without item_id returns every item's traces, so both are required.
  input: z.strictObject({ kind: scriptKind.describe('automation or script.'), id: itemId, ...page }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run({ kind, id, ...paging }, ctx) {
    const traces = await configRead<TraceSummary[]>(ctx, { type: 'trace/list', domain: kind, item_id: id });
    return text(pageOf('traces', traces.sort((a, b) => Date.parse(b.timestamp.start) - Date.parse(a.timestamp.start)), paging));
  },
});

/** The parts of a trace beyond its summary, returned only when asked for. */
const TRACE_SECTIONS = ['trace', 'config', 'blueprint_inputs', 'context'] as const;

const getTrace = defineTool({
  title: 'Get trace',
  description: [
    'Returns one run of an automation or script: its summary, plus the `sections` asked for.',
    'The sections are `trace` (each step with its variables and result), `config` (the config the run used), `blueprint_inputs` and `context` (what caused the run).',
    'Name the run by `kind`, `id` (an automation\'s config `id` or a script\'s object id) and `run_id` from its trace list.',
    'Secret-looking values come back as **REDACTED**, best-effort, and camera, image and media_player bearer tokens are removed.',
    'Example: {"kind": "automation", "id": "porch_light_1", "run_id": "1a2b3c", "sections": ["trace"]}.',
  ].join(' '),
  input: z.strictObject({
    kind: scriptKind.describe('automation or script.'),
    id: itemId,
    run_id: z.string().min(1).describe('The run, from its trace list.'),
    sections: z.array(z.enum(TRACE_SECTIONS)).min(1).describe('The parts to return beyond the summary.'),
  }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run({ kind, id, run_id, sections }, ctx) {
    const trace = await configRead<Record<string, unknown>>(ctx, { type: 'trace/get', domain: kind, item_id: id, run_id });
    const left = TRACE_SECTIONS.filter((s) => !sections.includes(s)) as string[];
    return text(Object.fromEntries(Object.entries(trace).filter(([key]) => !left.includes(key))));
  },
});

const targetIds = z.union([z.string(), z.array(z.string())]).optional();

interface HaService {
  name?: string;
  description?: string;
  fields?: Record<string, unknown>;
  target?: unknown;
  response?: unknown;
}

const listServices = defineTool({
  title: 'List services',
  description: [
    'Lists every service Home Assistant offers, sorted by name, each with its fields, whether it takes a target, whether it returns a response, and whether this Caller may call it (`callable`).',
    'A service marked callable may still be refused for a particular target that this Caller may not act on.',
    'Filter by `domain` (such as `light`).',
    PAGED,
    'Example: {"domain": "light"} lists the light services.',
  ].join(' '),
  input: z.strictObject({
    domain: slug.optional().describe('Service domain, such as light.'),
    ...page,
  }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run(args, ctx) {
    const all = await plainRead<Record<string, Record<string, HaService>>>(ctx, { type: 'get_services' });
    const services = Object.entries(all)
      .filter(([domain]) => args.domain === undefined || domain === args.domain)
      .flatMap(([domain, byName]) => Object.entries(byName).map(([name, d]) => ({ service: `${domain}.${name}`, d })))
      .sort((a, b) => a.service.localeCompare(b.service))
      .map(({ service, d }) => ({
        service,
        name: d.name,
        description: d.description,
        fields: d.fields ?? {},
        target: d.target !== undefined,
        response: d.response !== undefined,
        callable: callable(ctx.policy, ctx.auth.caller, service, d.target !== undefined),
      }));
    return text(pageOf('services', services, args));
  },
});

const callService = defineTool({
  title: 'Call a service',
  description: [
    'Calls a Home Assistant service, such as light.turn_on, with a `target` in any HA form (entity_id, device_id, area_id, floor_id, label_id, or entity_id "all") and service `data`.',
    'The server expands the target as Home Assistant would, leaves out entities of domains the service does not act on (a switch in an area for light.turn_on), and runs the call only if this Caller may act on every remaining entity; otherwise it refuses the whole call rather than narrowing it.',
    "Target keys inside `data` count as part of the target, and an entity_id named outside the service's domains is refused. A service that takes no target must be called without one.",
    'The result lists the entity_ids acted on, the HA context id and, for a service that responds, its response.',
    'Example: {"domain": "light", "service": "turn_on", "target": {"area_id": "kitchen"}, "data": {"brightness_pct": 40}}.',
  ].join(' '),
  input: z.strictObject({
    domain: slug.describe('Service domain, such as light.'),
    service: slug.describe('Service name, such as turn_on.'),
    target: z
      .strictObject({ entity_id: targetIds, device_id: targetIds, area_id: targetIds, floor_id: targetIds, label_id: targetIds })
      .optional()
      .describe('What the service acts on, in HA target form.'),
    data: z.record(z.string(), z.unknown()).optional().describe('Service data, such as {"brightness_pct": 40}.'),
  }),
  annotations: { readOnlyHint: false, destructiveHint: true },
  async run({ domain, service, target, data = {} }, ctx) {
    const name = `${domain}.${service}`;
    const requested = mergeTarget(target, data);
    const audit = (record: Record<string, unknown>) => ctx.audit({ service: name, target: requested, ...record });
    const refuse = (reason: string, message: string, record: Record<string, unknown> = {}) => {
      audit({ decision: 'deny', reason, ...record });
      return new ToolFailure(message);
    };
    const denial = failure(`Denied: this Caller holds no Grant to call ${name} over ${Object.keys(requested).length ? JSON.stringify(requested) : 'no target'}. Do not retry this call.`);

    const planned = planServiceCall(ctx.policy, ctx.auth.caller, name);
    if (!planned.plan) {
      audit({ decision: 'deny', grants: [], denies: planned.denies });
      return denial;
    }
    const { plan } = planned;
    const lookup = (command: Command) => send(ctx, plan.lookup, command);
    const description = ((await lookup({ type: 'get_services' })) as Record<string, Record<string, HaService> | undefined>)[domain]?.[service];
    if (!description) throw new ToolFailure(`Service ${name} not found.`);
    const targeted = description.target !== undefined;
    const hasTarget = Object.keys(requested).length > 0;
    if (targeted && !hasTarget) throw refuse('this service needs a target', `${name}: this service needs a target.`);
    if (!targeted && hasTarget) throw refuse('this service takes no target', `${name}: this service takes no target.`);

    const expansion = { targeted, entities: [] as string[], grantEntities: [] as string[], denyEntities: [] as string[] };
    if (targeted) {
      const reached = await extract(lookup, await expandAll(lookup, requested, name));
      const domains = domainsOf(description.target);
      const admitted = (e: string) => domains?.has(e.split('.')[0]!) ?? true;
      // An entity_id the Caller named is never left out silently.
      const named = (requested.entity_id ?? []).filter((e) => e !== 'all' && !admitted(e));
      if (named.length > 0) {
        throw refuse('entity outside the service domains', `${name} acts only on ${[...domains!].join(', ')} entities; remove ${named.join(', ')} from the target.`, { entities: named });
      }
      expansion.entities = reached.filter(admitted);
      if (expansion.entities.length === 0) throw refuse('target matches no entity', `${name}: target matches no entity.`);
      expansion.grantEntities = await extract(lookup, plan.grantSelectors);
      expansion.denyEntities = await extract(lookup, plan.denySelectors, false);
    }
    const decision = decideServiceCall(ctx.policy, plan, expansion, { domain, service, data, responds: description.response !== undefined });
    const { grants, uncovered } = decision;
    if (!decision.allowed) {
      audit({ decision: 'deny', entities: expansion.entities, grants, denies: decision.denies, uncovered });
      return denial;
    }
    // Recorded before sending, so a call that fails or ends "outcome unknown" still leaves a record.
    if (ctx.options.auditWrites) audit({ decision: 'allow', entities: expansion.entities, grants });
    const result = await send<{ context: { id: string }; response?: unknown }>(ctx, decision.allowed, decision.allowed.write.command);
    if (ctx.options.auditWrites) audit({ outcome: 'done', context_id: result.context.id });
    return writeResult({ entity_ids: expansion.entities, context_id: result.context.id, response: result.response });
  },
});

const writeConfig = defineTool({
  title: 'Write config',
  description: [
    'Creates, updates or deletes one automation, script, scene or helper (input_*, counter, timer or schedule); this is admin-equivalent, because an automation or script can do anything in Home Assistant.',
    "Name the item by `kind` and `id`: an automation's or scene's config `id`, a script's object id (the part after `script.`), or a helper's `<domain>.<id>`, such as input_boolean.guest_mode.",
    'An update sends only the top-level keys it changes and keeps the rest; creating an automation, script or scene refuses an id that exists, and a new helper takes its id from its `name`, which the result returns.',
    'A config that carries **REDACTED** from a config read is refused, so put the real value in its place first.',
    'Example: {"kind": "automation", "action": "update", "id": "porch_light_1", "config": {"alias": "Porch light at dusk"}}.',
  ].join(' '),
  input: z
    .strictObject({
      kind: configKind.describe('automation, script, scene or helper.'),
      action: z.enum(['create', 'update', 'delete']).describe('create, update or delete.'),
      id: z.string().min(1).describe("An automation's or scene's config id, a script's object id, or a helper's <domain>.<id>."),
      config: z.record(z.string(), z.unknown()).optional().describe('The config to create, or the top-level keys to change; omitted for delete.'),
    })
    .superRefine(({ kind, action, id, config }, ctx) => {
      if (kind === 'helper' && !helperId.test(id)) ctx.addIssue({ code: 'custom', path: ['id'], message: HELPER_ID_RULE });
      if (action !== 'delete' && config === undefined) ctx.addIssue({ code: 'custom', path: ['config'], message: `is required to ${action}` });
      if (action === 'delete' && config !== undefined) ctx.addIssue({ code: 'custom', path: ['config'], message: 'is not taken by delete' });
    }),
  annotations: { readOnlyHint: false, destructiveHint: true },
  decide: (change: ConfigWrite, policy, caller) => ({
    ...decideConfigWrite(policy, caller, change),
    lacking: `config writes of ${change.kind}`,
    request: { kind: change.kind, action: change.action, id: change.id },
  }),
  async run(change: ConfigWrite, ctx) {
    const { kind, action, id } = change;
    let allowed = ctx.allowed;
    if (!allowed) throw new Error('config write sent without an Allowed');
    const marked = redactedPath(change.config);
    if (marked !== undefined) {
      ctx.audit({ kind, action, id, decision: 'deny', reason: 'config carries a redacted value' });
      throw new ToolFailure(`config carries a redacted value at ${marked}: put the real value in its place. Nothing was sent to Home Assistant.`);
    }
    // A new helper takes its id from its name, so only a helper update has a stored item to look up.
    if (action === 'update' || (kind !== 'helper' && action === 'create')) {
      const lookup = decideConfigRead(ctx.policy, ctx.auth.caller, kind).allowed;
      const [domain, item] = splitHelperId(id);
      const stored =
        kind === 'helper'
          ? (await send<Record<string, unknown>[]>(ctx, lookup, { type: `${domain}/list` })).find((h) => h.id === item)
          : ((await rest(ctx, lookup, { method: 'GET', path: configPath(kind, id) })) as Record<string, unknown> | undefined);
      if (action === 'create' && stored) throw new ToolFailure(`The ${kind} ${id} already exists; update it instead.`);
      if (action === 'update' && !stored) throw new ToolFailure(`The ${kind} ${id} does not exist; create it instead.`);
      if (stored) allowed = mergedUpdate(allowed, stored);
    }
    if (ctx.options.auditWrites) ctx.audit({ kind, action, id, decision: 'allow', grants: ctx.grants });
    const { write } = allowed;
    if (!write) throw new Error('config write sent without a write');
    const result = write.via === 'websocket' ? await send(ctx, allowed, write.command) : await rest(ctx, allowed, write.request);
    // A helper write echoes the whole stored item, keys the Caller did not send included.
    return writeResult({ kind, action, id, result: maskSecrets(stripBearerTokens(result)) });
  },
});

const TOOLS: Record<ToolName, ToolSpec<z.ZodType>> = {
  ha_get_states: getStates,
  ha_get_history: getHistory,
  ha_get_logbook: getLogbook,
  ha_get_registry: getRegistry,
  ha_list_services: listServices,
  ha_get_config: getConfig,
  ha_list_traces: listTraces,
  ha_get_trace: getTrace,
  ha_write_config: writeConfig,
  ha_call_service: callService,
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
  ha_call_service: 'Before calling a service with ha_call_service, check in ha_list_services that it is callable and whether it takes a target.',
};
const GENERAL_INSTRUCTIONS = [
  'Every call is checked against the Grants this Caller holds. A denied call means there is no Grant for it, so do not retry it or try to reach the same result another way.',
  'Lists return `total` and `has_more`: while `has_more` is true, call again with `offset` raised by `limit`. A response that is too large is refused rather than cut off, so narrow the query and call again.',
];
const instructionsFor = (visible: ToolName[]) => [...visible.flatMap((name) => TOOL_INSTRUCTIONS[name] ?? []), ...GENERAL_INSTRUCTIONS].join('\n');

/** Allowed Operations are audited only on the deployer's opt-in, so reads don't drown the log. */
export interface AuditOptions {
  auditReads: boolean;
  auditWrites: boolean;
}

/**
 * One server per request, listing only the tools whose kind the Caller holds. A hidden tool called
 * directly is refused and audited before its input is read, so nothing reaches HA.
 */
export function buildServer(policy: Policy, gate: Gate, audit: Audit, auth: Authenticated, options: AuditOptions): Server {
  const holds = (name: ToolName) => grantsFor(policy, auth.caller, TOOL_KIND[name]).length > 0;
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
    const audited = auditFor(audit, auth, operation, name);
    if (!holds(name)) {
      audited({ decision: 'deny', grants: [] });
      return failure(`Denied: this Caller holds no Grant for ${OPERATION_NAME[operation]}. Do not retry this call.`);
    }
    const tool = TOOLS[name];
    const args = tool.input.safeParse(params.arguments ?? {});
    if (!args.success) {
      return failure(`Input validation error: ${args.error.issues.map((i) => `${i.path.join('.') || '(arguments)'}: ${i.message}`).join('; ')}`);
    }
    const decided = tool.decide?.(args.data, policy, auth.caller) ?? {
      ...(operation === 'plain_read' || operation === 'config_read' ? decideRead(policy, auth.caller, operation) : { grants: grantsFor(policy, auth.caller, operation) }),
      lacking: OPERATION_NAME[operation],
      request: {},
    };
    if (decided.grants.length === 0) {
      audited({ ...decided.request, decision: 'deny', grants: [] });
      return failure(`Denied: this Caller holds no Grant for ${decided.lacking}. Do not retry this call.`);
    }
    if (options.auditReads && READS.has(operation)) {
      audited({ decision: 'allow', grants: decided.grants, request: args.data });
    }
    try {
      const result = await tool.run(args.data, { ...decided, policy, auth, gate, audit: audited, options });
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
