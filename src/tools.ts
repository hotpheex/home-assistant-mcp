import { ProtocolError, ProtocolErrorCode, Server, type CallToolResult, type Tool } from '@modelcontextprotocol/server';
import * as z from 'zod';
import pkg from '../package.json' with { type: 'json' };
import type { Authenticated } from './auth.ts';
import {
  callable,
  collectionOf,
  configPath,
  dashboardDelete,
  dashboardPath,
  decideConfigRead,
  decideConfigWrite,
  decideHelperFlow,
  decideRead,
  decideServiceCall,
  ENTITY_NAME_FIELDS,
  FLOW_ID,
  grantsFor,
  HELPER_DOMAINS,
  mergedUpdate,
  planServiceCall,
  writersOf,
  type Allowed,
  type ConfigKind,
  type ConfigWrite,
  type HelperFlow,
  type Operation,
  decideBlueprintWrite,
  type BlueprintWrite,
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
  ha_get_statistics: 'plain_read',
  ha_render_template: 'plain_read',
  ha_get_logs: 'config_read',
  ha_get_dashboard: 'plain_read',
  ha_list_blueprints: 'config_read',
  ha_write_blueprint: 'config_write',
  ha_helper_flow: 'config_write',
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
  /** A config-write tool that serves only these kinds is listed only to a Caller holding one of them. */
  kinds?: readonly ConfigKind[];
  /** For a decision that needs the arguments, not just the tool's kind. */
  decide?(args: z.output<Input>, policy: Policy, caller: string): Decided;
  /** The arguments an allowed read's audit names, for a tool whose input is more than names. */
  auditable?(args: z.output<Input>): Record<string, unknown>;
  run(args: z.output<Input>, ctx: Context): Promise<CallToolResult>;
}

const PAGED = 'Results come in pages: `limit` (default 50, at most 500) and `offset` pick the page, and the response gives `total` and `has_more`.';
const MASKED = 'Values that look like secrets, such as passwords, tokens, API keys and URL credentials, come back as **REDACTED**; this is best-effort, so other secrets may still show.';
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
/**
 * A backwards window is refused before anything is sent: HA answers it with a made-up row or nothing.
 * Times go to HA to the millisecond, so `summarise` can match the stamp of HA's window-start row.
 */
function windowOf(args: { start?: string; end?: string }, hours: number) {
  const end = args.end === undefined ? Date.now() : Date.parse(args.end);
  const start = args.start === undefined ? end - hours * 3_600_000 : Date.parse(args.start);
  const [from, to] = [new Date(start).toISOString(), new Date(end).toISOString()];
  if (start > end) throw new ToolFailure(`Input validation error: start ${from} is after end ${to}.`);
  return { start: from, end: to };
}
/** HA sends times as float seconds. */
const isoOf = (seconds: number) => new Date(Math.round(seconds * 1000)).toISOString();

/**
 * Claude Code saves a text result over 50,000 characters to a file and shows only a preview, so the cap
 * sits below that, counted as Claude Code counts: string length, not bytes.
 */
const CHAR_CAP = 48_000;
/** Each read tool's size refusal names only the narrowing that tool offers. */
const NARROWING: Partial<Record<ToolName, string>> = {
  ha_get_states: 'the domain, state, query, area or label filters, `full` off, or a smaller limit',
  ha_get_history: 'fewer entity_ids, a shorter window, `summary` or a smaller limit',
  ha_get_logbook: 'an entity_id, a shorter window or a smaller limit',
  ha_get_registry: 'a query or a smaller limit',
  ha_list_services: 'a domain or a smaller limit',
  ha_list_traces: 'a smaller limit',
  ha_get_trace: 'fewer sections',
  ha_get_statistics: 'a query, fewer statistic_ids, a shorter window, a longer period, fewer types or a smaller limit',
  ha_render_template: 'a template that renders less',
  ha_get_logs: 'a level, a query or a smaller limit',
  ha_list_blueprints: 'a domain or a smaller limit',
};
const charsOf = (result: CallToolResult) => result.content.reduce((n, c) => n + (c.type === 'text' ? c.text.length : 0), 0);
const READS: ReadonlySet<Operation> = new Set(['plain_read', 'config_read']);

const text = (value: unknown): CallToolResult => ({ content: [{ type: 'text', text: JSON.stringify(value) }] });
const failure = (message: string): CallToolResult => ({ isError: true, content: [{ type: 'text', text: message }] });

/** A failure the Caller can act on, returned as an isError result. */
class ToolFailure extends Error {
  /** HA's error code, when HA refused the request. */
  code?: string;
}

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

/** HA's refusals and outages become failures the Caller can act on. */
async function answered(request: Promise<unknown>): Promise<unknown> {
  try {
    return stripBearerTokens(await request);
  } catch (e) {
    const refusal = e as { code?: unknown; message?: unknown } | null;
    // HA's error results arrive as plain {code, message} objects, never as Errors.
    if (!(e instanceof Error) && typeof refusal?.code === 'string' && typeof refusal.message === 'string') {
      throw Object.assign(new ToolFailure(`Home Assistant refused the request: ${refusal.message}`), { code: refusal.code });
    }
    throw outage(e);
  }
}

/** Sends over WebSocket. */
async function send<T>(ctx: Context, allowed: Allowed | undefined, command: Command): Promise<T> {
  if (!allowed) throw new Error('sent without an Allowed');
  return (await answered(ctx.gate.send(allowed, command))) as T;
}

/** A write has already run, so an oversize response is cut with a visible marker rather than refused. */
function writeResult(value: unknown): CallToolResult {
  const full = JSON.stringify(value);
  if (full.length <= CHAR_CAP) return text(value);
  const marker = `\n[truncated: the response was ${full.length} characters, over the ${CHAR_CAP}-character cap; the call ran]`;
  const kept = full.slice(0, CHAR_CAP - marker.length).replace(/[\uD800-\uDBFF]$/, '');
  return { content: [{ type: 'text', text: kept + marker }] };
}

/** Every read masks secrets, so Redaction means one thing on every read. */
const read = async <T>(ctx: Context, command: Command) => maskSecrets(await send(ctx, ctx.allowed, command)) as T;

/** Sends a config REST request; HA's error statuses become failures, except a 404 on GET, which means no such item. */
async function rest(ctx: Context, allowed: Allowed | undefined, request: RestRequest): Promise<unknown> {
  if (!allowed) throw new Error('REST sent without an Allowed');
  const answer = await ctx.gate.rest(allowed, request).catch((e: unknown) => {
    throw outage(e);
  });
  if (answer.status === 404 && request.method === 'GET') return undefined;
  // A flow step that fails HA's schema answers 400 with field errors, and the flow stays open.
  const errors = (answer.body as { errors?: unknown } | null)?.errors;
  if (answer.status === 400 && errors !== undefined) {
    throw new ToolFailure(`Home Assistant refused the input: ${JSON.stringify(maskSecrets(errors))}. The flow is still open: correct the input and submit the step again.`);
  }
  if (answer.status !== 200) {
    const message = (answer.body as { message?: string } | null)?.message ?? `HTTP ${answer.status}`;
    throw new ToolFailure(`Home Assistant refused the request: ${message}`);
  }
  return answer.body;
}

/** A stored scene, automation, script, helper or zone by its write id, unmasked, so a write can merge it; undefined if there is none. */
async function stored(ctx: Context, allowed: Allowed | undefined, kind: ConfigWrite['kind'], id: string): Promise<Record<string, unknown> | undefined> {
  const collection = collectionOf(kind, id);
  if (!collection) return (await rest(ctx, allowed, { method: 'GET', path: configPath(kind, id) })) as Record<string, unknown> | undefined;
  const [domain, item] = collection;
  return (await send<Record<string, unknown>[]>(ctx, allowed, { type: `${domain}/list` })).find((h) => h.id === item);
}

/** Only the list says whether a dashboard exists, so a listed one with no saved layout merges over nothing. */
async function dashboardLookup(ctx: Context, { action, id }: ConfigWrite, allowed: Allowed): Promise<Allowed> {
  const lookup = decideConfigRead(ctx.policy, ctx.auth.caller, 'dashboard').allowed;
  const listed = id === 'lovelace' ? [{ url_path: id }] : await send<{ id?: string; url_path: string }[]>(ctx, lookup, { type: 'lovelace/dashboards/list' });
  const item = listed.find((d) => d.url_path === id);
  if (action === 'create' && item) throw new ToolFailure(`The dashboard ${id} already exists; update it instead.`);
  if (action === 'create') return allowed;
  if (!item) throw new ToolFailure(`The dashboard ${id} does not exist; create it instead.`);
  if (action === 'update') {
    const layout = await send<Record<string, unknown>>(ctx, lookup, { type: 'lovelace/config', ...dashboardPath(id) }).catch((e: unknown) => {
      if (e instanceof ToolFailure && e.code === 'config_not_found') return {};
      throw e;
    });
    return mergedUpdate(allowed, layout);
  }
  if (item.id === undefined) throw new ToolFailure(`The dashboard ${id} is defined in YAML, so only its YAML can remove it.`);
  return dashboardDelete(allowed, item.id);
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
    read<RegistryEntity[]>(ctx, { type: 'config/entity_registry/list' }),
    read<{ id: string; area_id: string | null }[]>(ctx, { type: 'config/device_registry/list' }),
    read<{ area_id: string; name: string }[]>(ctx, { type: 'config/area_registry/list' }),
    read<{ label_id: string; name: string }[]>(ctx, { type: 'config/label_registry/list' }),
  ]);
  // Only the extended entries carry aliases.
  const extended = await read<Record<string, { aliases?: (string | null)[] } | null>>(ctx, {
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
    'Filter by `domain` (such as `light`), by exact `state` (such as `on`), and by `query`, a case-insensitive substring of the entity_id, friendly name, aliases, or area and label names; filter by `area` or `label` id to get what a Home Assistant service call targeting that area or label acts on.',
    'Attributes are left out unless `full` is true; bearer tokens in camera, image and media_player attributes are always removed.',
    MASKED,
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
    const states = await read<HaState[]>(ctx, { type: 'get_states' });
    const query = args.query?.toLowerCase();
    const names = query === undefined ? new Map<string, string[]>() : await registryNames(ctx);
    const within = async (key: 'area_id' | 'label_id', id: string | undefined) =>
      id === undefined ? undefined : new Set(await extract((command) => read(ctx, command), { [key]: [id] }));
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

/** HA keeps the history of a deleted or renamed entity, so a named entity_id that is not current is noted, not refused. */
async function notCurrent(ctx: Context, entityIds: string[]) {
  const current = new Set((await read<HaState[]>(ctx, { type: 'get_states' })).map((s) => s.entity_id));
  const missing = entityIds.filter((id) => !current.has(id));
  return missing.length > 0 ? { not_current_entity_ids: missing } : {};
}

type HistoryRow = { s: string; lu: number; lc?: number };

/**
 * One entity's window: HA's first row is the state at the start when stamped with the start time, so it is not a change.
 * The numeric mean weights each value by how long it held, leaving out unknown, unavailable and other non-numeric stretches.
 */
function summarise(entity_id: string, rows: HistoryRow[], start: string, end: string) {
  const [from, to] = [Date.parse(start), Date.parse(end)];
  const atStart = rows[0] !== undefined && Math.round(rows[0].lu * 1000) === from;
  const summary = { entity_id, changes: rows.length - (atStart ? 1 : 0), first: rows[0]?.s, last: rows.at(-1)?.s };
  const at = (row: HistoryRow) => Math.max(from, Math.round((row.lc ?? row.lu) * 1000));
  const numbers: number[] = [];
  let [weighted, held, skipped] = [0, 0, 0];
  for (const [i, row] of rows.entries()) {
    const value = row.s.trim() === '' ? NaN : Number(row.s);
    if (!Number.isFinite(value)) {
      skipped += 1;
      continue;
    }
    const next = rows[i + 1];
    const span = (next ? at(next) : to) - at(row);
    numbers.push(value);
    weighted += value * span;
    held += span;
  }
  if (numbers.length > 0) {
    const mean = held > 0 ? weighted / held : numbers.reduce((a, b) => a + b, 0) / numbers.length;
    return { ...summary, min: numbers.reduce((a, b) => Math.min(a, b)), max: numbers.reduce((a, b) => Math.max(a, b)), mean, skipped };
  }
  const counts: Record<string, number> = {};
  for (const row of rows) counts[row.s] = (counts[row.s] ?? 0) + 1;
  return { ...summary, states: counts };
}

const getHistory = defineTool({
  title: 'Get entity history',
  description: [
    'Lists the state changes of the given entities over a time window, without attributes, one row per change with its entity_id, state and last_changed time, sorted by entity_id and then time; each entity\'s first row is the state it already had at the window start, stamped with the start time.',
    'The window defaults to the last 24 hours; `start` and `end` take ISO 8601 times, and a `start` after `end` is refused; a named entity_id that is not a current entity is still read, because HA keeps the history of deleted and renamed entities, and is listed in `not_current_entity_ids`.',
    'With `summary` it returns one entry per entity instead: the number of changes after the window start, the state at the window start and the last state, and either the minimum, maximum and time-weighted mean of numeric states, with `skipped` counting the unknown, unavailable and other non-numeric states left out, or a count of each state.',
    MASKED,
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
    const [changes, missing] = await Promise.all([
      read<Record<string, HistoryRow[]>>(ctx, {
        type: 'history/history_during_period',
        start_time: start,
        end_time: end,
        entity_ids: args.entity_ids,
        no_attributes: true,
      }),
      notCurrent(ctx, args.entity_ids),
    ]);
    const ids = Object.keys(changes).sort();
    const entries = args.summary
      ? ids.map((id) => summarise(id, changes[id]!, start, end))
      : ids.flatMap((id) => changes[id]!.map((c) => ({ entity_id: id, state: c.s, last_changed: isoOf(c.lc ?? c.lu) })));
    return text({ start, end, ...missing, ...pageOf('history', entries, args) });
  },
});

const getLogbook = defineTool({
  title: 'Get logbook',
  description: [
    'Lists Home Assistant logbook entries over a time window, oldest first: what changed or happened, when, and the context that caused it.',
    'The window defaults to the last hour; `start` and `end` take ISO 8601 times, and `entity_id` keeps only one entity\'s entries.',
    'A `start` after `end` is refused; an `entity_id` that is not a current entity is still read, because HA keeps the logbook of deleted and renamed entities, and is listed in `not_current_entity_ids`.',
    MASKED,
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
    const [entries, missing] = await Promise.all([
      read<{ when: number }[]>(ctx, {
        type: 'logbook/get_events',
        start_time: start,
        end_time: end,
        ...(args.entity_id !== undefined && { entity_ids: [args.entity_id] }),
      }),
      args.entity_id === undefined ? {} : notCurrent(ctx, [args.entity_id]),
    ]);
    return text({ start, end, ...missing, ...pageOf('entries', entries.map((e) => ({ ...e, when: isoOf(e.when) })), args) });
  },
});

const mentions = (value: unknown, query: string): boolean =>
  typeof value === 'string'
    ? value.toLowerCase().includes(query)
    : typeof value === 'object' && value !== null && Object.values(value).some((v) => mentions(v, query));

const getRegistry = defineTool({
  title: 'Get registry',
  description: [
    'Lists the entries of one Home Assistant registry, in registry order: `entity`, `device`, `area`, `label` or `floor`.',
    'Entries are returned as Home Assistant stores them, with ids, names and the area, floor, device and label ids that link them.',
    '`query` keeps entries with any text value that contains it, case-insensitively: an id, a name or an alias, and nested values too, such as a device\'s MAC address or identifiers; fixed values such as `disabled_by` match too, so "user" also finds entries a user disabled.',
    MASKED,
    PAGED,
    'Example: {"registry": "area", "query": "kitchen"} finds the kitchen area and its floor_id.',
  ].join(' '),
  input: z.strictObject({
    registry: z.enum(['entity', 'device', 'area', 'label', 'floor']).describe('The registry to list.'),
    query: z.string().min(1).optional().describe('Case-insensitive substring of any text value in an entry, nested ones included.'),
    ...page,
  }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run(args, ctx) {
    const entries = await read<Record<string, unknown>[]>(ctx, { type: `config/${args.registry}_registry/list` });
    const query = args.query?.toLowerCase();
    return text(pageOf('entries', query === undefined ? entries : entries.filter((e) => mentions(e, query)), args));
  },
});

const STATISTIC_TYPES = ['min', 'max', 'mean', 'sum', 'state', 'change'] as const;
type StatisticRow = { start: number; end: number } & Record<string, unknown>;

const getStatistics = defineTool({
  title: 'Get long-term statistics',
  description: [
    'Without `statistic_ids`, lists the long-term statistics Home Assistant keeps, sorted by statistic_id, with each one\'s name, unit and source; `query` keeps those whose statistic_id or name contains it, case-insensitively.',
    'With `statistic_ids`, returns one row per statistic and `period` (`5minute`, `hour`, `day`, `week` or `month`; default `hour`), sorted by statistic_id and then time, with its start and end and the chosen `types` (`min`, `max`, `mean`, `sum`, `state` and `change`; default all), null where a statistic does not keep that type.',
    'The window defaults to the last 7 days; `start` and `end` take ISO 8601 times, and a `start` after `end` is refused.',
    MASKED,
    PAGED,
    'Example: {"statistic_ids": ["sensor.grid_energy"], "period": "month", "types": ["change"], "start": "2026-01-01T00:00:00Z"} gives the energy used each month this year.',
  ].join(' '),
  input: z
    .strictObject({
      query: z.string().min(1).optional().describe('Listing only: case-insensitive substring of the statistic_id or name.'),
      statistic_ids: z.array(z.string().min(1)).min(1).optional().describe('The statistics to read, such as ["sensor.grid_energy"]; leave out to list them.'),
      period: z.enum(['5minute', 'hour', 'day', 'week', 'month']).default('hour').describe('The length of each row.'),
      types: z.array(z.enum(STATISTIC_TYPES)).min(1).default([...STATISTIC_TYPES]).describe('The values each row carries.'),
      ...window,
      ...page,
    })
    // An argument of the other mode is refused rather than silently ignored.
    .superRefine(({ query, statistic_ids, start, end }, ctx) => {
      if (statistic_ids !== undefined && query !== undefined) ctx.addIssue({ code: 'custom', path: ['query'], message: 'is taken only when listing, without statistic_ids' });
      for (const [key, value] of Object.entries({ start, end })) {
        if (statistic_ids === undefined && value !== undefined) ctx.addIssue({ code: 'custom', path: [key], message: 'is taken only with statistic_ids' });
      }
    }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run(args, ctx) {
    if (args.statistic_ids === undefined) {
      const query = args.query?.toLowerCase();
      const ids = (await read<{ statistic_id: string; name: string | null }[]>(ctx, { type: 'recorder/list_statistic_ids' }))
        .filter((s) => query === undefined || [s.statistic_id, s.name ?? ''].some((v) => v.toLowerCase().includes(query)))
        .sort((a, b) => a.statistic_id.localeCompare(b.statistic_id));
      return text(pageOf('statistic_ids', ids, args));
    }
    const { start, end } = windowOf(args, 7 * 24);
    const periods = await read<Record<string, StatisticRow[]>>(ctx, {
      type: 'recorder/statistics_during_period',
      start_time: start,
      end_time: end,
      statistic_ids: args.statistic_ids,
      period: args.period,
      types: args.types,
    });
    const rows = Object.keys(periods)
      .sort()
      .flatMap((id) => periods[id]!.map((r) => ({ statistic_id: id, ...r, start: new Date(r.start).toISOString(), end: new Date(r.end).toISOString() })));
    return text({ start, end, period: args.period, ...pageOf('statistics', rows, args) });
  },
});

const scriptKind = z.enum(['automation', 'script']);
const itemId = z.string().min(1).describe("The automation's config `id`, or the script's object id (the part after `script.`).");

const configKind = z.enum(CONFIG_KINDS);
const helperId = new RegExp(`^(${HELPER_DOMAINS.join('|')})\\.[a-z0-9_]+$`);
const HELPER_ID_RULE = 'must be <helper domain>.<id>, such as input_boolean.guest_mode';
const NOT_A_CONFIG = 'a wizard helper is set up through its flow, not as a config';

const getConfig = defineTool({
  title: 'Get config',
  description: [
    'Returns the stored configuration of one automation, script, scene, helper (input_*, counter, timer or schedule) or zone.',
    'Name an automation or script by `kind` and `entity_id`, such as automation.porch_light; a scene or zone by its config `id`; and a helper by `id` as `<domain>.<id>`, such as input_boolean.guest_mode.',
    'Scene, helper and zone configs are served only to a Caller that may write that kind.',
    MASKED,
    'Example: {"kind": "automation", "entity_id": "automation.porch_light"}.',
  ].join(' '),
  input: z
    .strictObject({
      kind: configKind.describe('automation, script, scene, helper or zone.'),
      entity_id: entityId.optional().describe('For an automation or script: its entity, such as automation.porch_light.'),
      id: z.string().min(1).optional().describe('For a scene or zone: its config id. For a helper: <domain>.<id>, such as input_boolean.guest_mode.'),
    })
    .superRefine(({ kind, entity_id, id }, ctx) => {
      const byEntity = kind === 'automation' || kind === 'script';
      const a = kind === 'automation' ? 'an' : 'a';
      const [taken, other] = byEntity ? (['entity_id', 'id'] as const) : (['id', 'entity_id'] as const);
      if ({ entity_id, id }[other] !== undefined) ctx.addIssue({ code: 'custom', path: [other], message: `is not taken for ${a} ${kind}, which takes only ${taken}` });
      if (byEntity && entity_id === undefined) ctx.addIssue({ code: 'custom', path: ['entity_id'], message: `is required for ${a} ${kind}` });
      if (byEntity && entity_id?.startsWith(`${kind}.`) === false) {
        ctx.addIssue({ code: 'custom', path: ['entity_id'], message: `its domain must match kind: ${a} ${kind} takes ${kind}.<id>` });
      }
      if (!byEntity && id === undefined) ctx.addIssue({ code: 'custom', path: ['id'], message: `is required for a ${kind}` });
      if (kind === 'helper' && id !== undefined && !helperId.test(id)) ctx.addIssue({ code: 'custom', path: ['id'], message: HELPER_ID_RULE });
      if (kind === 'entity_name') ctx.addIssue({ code: 'custom', path: ['kind'], message: "entity_name has no config to read; ha_get_registry lists each entity's name and icon" });
      if (kind === 'dashboard') ctx.addIssue({ code: 'custom', path: ['kind'], message: 'a dashboard is read with the dashboard tool' });
      if (kind === 'helper_entry') ctx.addIssue({ code: 'custom', path: ['kind'], message: NOT_A_CONFIG });
    }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  decide: ({ kind }, policy, caller) => ({ ...decideConfigRead(policy, caller, kind), lacking: `${kind} config`, request: { kind } }),
  async run({ kind, entity_id, id }, ctx) {
    if (kind === 'automation' || kind === 'script') return text(await read(ctx, { type: `${kind}/config`, entity_id }));
    const config = await stored(ctx, ctx.allowed, kind, id!);
    if (config === undefined) throw new ToolFailure(`${kind.charAt(0).toUpperCase()}${kind.slice(1)} ${id} not found.`);
    return text({ config: maskSecrets(stripBearerTokens(config)) });
  },
});

type TraceSummary = { timestamp: { start: string } };

/**
 * Refuses a trace call whose id names no automation or script, so a wrong id is not read as no runs.
 * The registry's unique_id is the config id or object id, YAML automations included.
 */
async function assertItemExists(ctx: Context, kind: string, id: string) {
  const entities = await send<{ platform: string; unique_id: string }[]>(ctx, ctx.allowed, { type: 'config/entity_registry/list' });
  if (entities.some((e) => e.platform === kind && e.unique_id === id)) return;
  throw new ToolFailure(`No ${kind} has the id ${id}. Name it by an automation's config id or a script's object id (the part after script.), not by its entity_id.`);
}

const listTraces = defineTool({
  title: 'List traces',
  description: [
    'Lists the stored runs of one automation or script, newest first, as summaries: run_id, start and finish time, state, last step, what triggered it and any error.',
    'Name the item by `kind` (automation or script) and `id`: an automation\'s config `id` from its config, or a script\'s object id, the part of its entity_id after `script.`.',
    'An id that names no automation or script is refused; one with no stored runs returns an empty list.',
    MASKED,
    PAGED,
    'Example: {"kind": "script", "id": "morning"} lists the runs of script.morning.',
  ].join(' '),
  // HA's trace/list without item_id returns every item's traces, so both are required.
  input: z.strictObject({ kind: scriptKind.describe('automation or script.'), id: itemId, ...page }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run({ kind, id, ...paging }, ctx) {
    const traces = await read<TraceSummary[]>(ctx, { type: 'trace/list', domain: kind, item_id: id });
    if (traces.length === 0) await assertItemExists(ctx, kind, id);
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
    'Camera, image and media_player bearer tokens are removed.',
    MASKED,
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
    const trace = await read<Record<string, unknown>>(ctx, { type: 'trace/get', domain: kind, item_id: id, run_id }).catch(async (e: unknown) => {
      if (e instanceof ToolFailure) await assertItemExists(ctx, kind, id);
      throw e;
    });
    const left = TRACE_SECTIONS.filter((s) => !sections.includes(s)) as string[];
    return text(Object.fromEntries(Object.entries(trace).filter(([key]) => !left.includes(key))));
  },
});

const LOG_LEVELS = ['debug', 'info', 'warning', 'error', 'critical'] as const;
type LogEntry = { name: string; level: string; message: string[]; source: unknown[]; timestamp: number; first_occurred: number };

const getLogs = defineTool({
  title: 'Get system log',
  description: [
    "Lists Home Assistant's system log, newest first: the warnings and errors that integrations and automations logged, each with its logger name, level, messages, source file and line, exception text, count, and the first and last times it occurred.",
    'Filter by minimum `level` (debug, info, warning, error or critical) and by `query`, a case-insensitive substring of the logger name, the source or a message.',
    MASKED,
    PAGED,
    'Example: {"level": "error", "query": "automation"} lists the errors automations logged.',
  ].join(' '),
  input: z.strictObject({
    level: z.enum(LOG_LEVELS).optional().describe('The lowest level to list.'),
    query: z.string().min(1).optional().describe('Case-insensitive substring of the logger name, the source or a message.'),
    ...page,
  }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  // The query matches the masked text, so it cannot probe for a secret.
  async run({ level, query, ...paging }, ctx) {
    const entries = await read<LogEntry[]>(ctx, { type: 'system_log/list' });
    const rank = (name: string) => LOG_LEVELS.findIndex((l) => l === name.toLowerCase());
    const shown = entries
      .filter((e) => level === undefined || rank(e.level) >= rank(level))
      .filter((e) => query === undefined || [e.name, e.source.join(':'), ...e.message].some((v) => v.toLowerCase().includes(query.toLowerCase())))
      .map((e) => ({ ...e, timestamp: isoOf(e.timestamp), first_occurred: isoOf(e.first_occurred) }));
    return text(pageOf('entries', shown, paging));
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
    MASKED,
    PAGED,
    'Example: {"domain": "light"} lists the light services.',
  ].join(' '),
  input: z.strictObject({
    domain: slug.optional().describe('Service domain, such as light.'),
    ...page,
  }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run(args, ctx) {
    const all = await read<Record<string, Record<string, HaService>>>(ctx, { type: 'get_services' });
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

/** Sidebar settings after creation and HA's `allow_single_word` are out of reach. */
const DASHBOARD_SIDEBAR = ['title', 'icon', 'show_in_sidebar', 'require_admin'];

const writeConfig = defineTool({
  title: 'Write config',
  description: [
    'Creates, updates or deletes one automation, script, scene, helper (input_*, counter, timer or schedule), zone or dashboard; this is admin-equivalent, because an automation or script can do anything in Home Assistant.',
    "Name the item by `kind` and `id`: an automation's, scene's or zone's config `id`, a script's object id (the part after `script.`), a helper's `<domain>.<id>`, such as input_boolean.guest_mode, or a dashboard's URL path, where `lovelace`, the default dashboard, can only be updated; a new dashboard takes only its sidebar settings (`title`, `icon`, `show_in_sidebar`, `require_admin`).",
    'An update sends only the top-level keys it changes and keeps the rest; creating an automation, script or scene refuses an id that exists, and a new helper or zone takes its id from its `name`, which the result returns.',
    'A config that carries **REDACTED** from a config read is refused, so put the real value in its place first.',
    'Example: {"kind": "automation", "action": "update", "id": "porch_light_1", "config": {"alias": "Porch light at dusk"}}.',
    'Kind `entity_name` only updates the `name`, `icon` or `aliases` of the entity whose entity_id is `id`; voice assistants match its aliases.',
  ].join(' '),
  input: z
    .strictObject({
      kind: configKind.describe('automation, script, scene, helper, zone, entity_name or dashboard.'),
      action: z.enum(['create', 'update', 'delete']).describe('create, update or delete.'),
      id: z.string().min(1).describe("An automation's, scene's or zone's config id, a script's object id, a helper's <domain>.<id>, an entity_name's entity_id, or a dashboard's URL path."),
      config: z.record(z.string(), z.unknown()).optional().describe('The config to create, or the top-level keys to change; omitted for delete.'),
    })
    .superRefine(({ kind, action, id, config }, ctx) => {
      if (kind === 'helper' && !helperId.test(id)) ctx.addIssue({ code: 'custom', path: ['id'], message: HELPER_ID_RULE });
      if (action !== 'delete' && config === undefined) ctx.addIssue({ code: 'custom', path: ['config'], message: `is required to ${action}` });
      if (action === 'delete' && config !== undefined) ctx.addIssue({ code: 'custom', path: ['config'], message: 'is not taken by delete' });
      if (kind === 'entity_name' && action !== 'update') ctx.addIssue({ code: 'custom', path: ['action'], message: 'entity_name takes only update' });
      if (kind === 'entity_name' && !entityId.safeParse(id).success) ctx.addIssue({ code: 'custom', path: ['id'], message: 'must be an entity_id such as light.kitchen' });
      for (const key of kind === 'entity_name' ? Object.keys(config ?? {}) : []) {
        const allowed = (ENTITY_NAME_FIELDS as readonly string[]).includes(key);
        if (!allowed) ctx.addIssue({ code: 'custom', path: ['config', key], message: 'entity_name changes only name, icon and aliases' });
      }
      if (kind === 'dashboard' && id === 'lovelace' && action !== 'update') ctx.addIssue({ code: 'custom', path: ['id'], message: 'the default dashboard lovelace can only be updated' });
      if (kind === 'dashboard' && action === 'create' && Object.keys(config ?? {}).some((k) => !DASHBOARD_SIDEBAR.includes(k))) {
        ctx.addIssue({ code: 'custom', path: ['config'], message: 'a new dashboard takes only title, icon, show_in_sidebar and require_admin' });
      }
      if (kind === 'helper_entry') ctx.addIssue({ code: 'custom', path: ['kind'], message: NOT_A_CONFIG });
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
    // Recorded before the lookup, so a write refused by its lookup, failed, or of unknown outcome still leaves a record.
    if (ctx.options.auditWrites) ctx.audit({ kind, action, id, decision: 'allow', grants: ctx.grants });
    if (kind === 'dashboard') allowed = await dashboardLookup(ctx, change, allowed);
    // A new helper or zone takes its id from its name, so only a collection update has a stored item to look up; HA's registry update is partial.
    else if (kind !== 'entity_name' && (action === 'update' || (!collectionOf(kind, id) && action === 'create'))) {
      const item = await stored(ctx, decideConfigRead(ctx.policy, ctx.auth.caller, kind).allowed, kind, id);
      if (action === 'create' && item) throw new ToolFailure(`The ${kind} ${id} already exists; update it instead.`);
      if (action === 'update' && !item) throw new ToolFailure(`The ${kind} ${id} does not exist; create it instead.`);
      if (item) allowed = mergedUpdate(allowed, item);
    }
    const { write } = allowed;
    if (!write) throw new Error('config write sent without a write');
    const result = write.via === 'websocket' ? await send(ctx, allowed, write.command) : await rest(ctx, allowed, write.request);
    if (ctx.options.auditWrites) ctx.audit({ kind, action, id, outcome: 'done' });
    // A helper or zone write echoes the whole stored item, keys the Caller did not send included.
    return writeResult({ kind, action, id, result: maskSecrets(stripBearerTokens(result)) });
  },
});

const renderTemplate = defineTool({
  title: 'Render template',
  description: [
    'Renders one Home Assistant template, such as one meant for an automation, and returns its `result` and the `listeners` (entities, domains and time) that would render it again, or Home Assistant\'s template error.',
    'Undefined names are errors, as in Home Assistant\'s template editor, so give the values of the template\'s own names in `variables`.',
    'A render that takes longer than `timeout` seconds (default 5, at most 30) fails.',
    MASKED,
    'Example: {"template": "{{ states(\'sensor.kitchen_temperature\') | float > 20 }}"} tells whether the kitchen is above 20 degrees.',
  ].join(' '),
  input: z.strictObject({
    template: z.string().min(1).describe('The template, such as {{ states(\'light.kitchen\') }}.'),
    variables: z.record(z.string(), z.unknown()).optional().describe('Values for names the template uses.'),
    timeout: z.number().positive().max(30).default(5).describe('Seconds the render may take, at most 30.'),
  }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  // A template and its variables may carry anything, so the audit names only the timeout.
  auditable: ({ timeout }) => ({ timeout }),
  async run(args, ctx) {
    if (!ctx.allowed) throw new Error('rendered without an Allowed');
    // Strict, because otherwise an undefined name sends a warning event before the result; HA drops render errors unless reported.
    const command = { type: 'render_template', template: args.template, ...(args.variables && { variables: args.variables }), timeout: args.timeout, strict: true, report_errors: true };
    const event = (await answered(ctx.gate.subscribeOnce(ctx.allowed, command))) as { error?: string };
    if (event.error !== undefined) throw new ToolFailure(`Home Assistant could not render the template: ${event.error}`);
    return text(maskSecrets(event));
  },
});

const getDashboard = defineTool({
  title: 'Get dashboard',
  description: [
    'Without `dashboard`, lists the dashboards stored in Home Assistant, each with its URL path, title and sidebar settings.',
    'With `dashboard`, returns that dashboard\'s stored layout; `lovelace` names the default dashboard.',
    'A dashboard whose layout Home Assistant generates has no stored layout, so reading it is refused.',
    MASKED,
    'Example: {"dashboard": "kitchen-wall"}.',
  ].join(' '),
  input: z.strictObject({
    dashboard: z.string().min(1).optional().describe('A dashboard URL path, such as kitchen-wall; lovelace is the default dashboard.'),
  }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run({ dashboard }, ctx) {
    if (dashboard === undefined) return text({ dashboards: await read(ctx, { type: 'lovelace/dashboards/list' }) });
    return text({ dashboard, config: await read(ctx, { type: 'lovelace/config', ...dashboardPath(dashboard) }) });
  },
});

type BlueprintEntry = { metadata: { name: string; description?: string; input?: unknown; source_url?: string } } | { error: string };

const listBlueprints = defineTool({
  title: 'List blueprints',
  description: [
    'Lists the installed automation and script blueprints, sorted by domain and path, each with its name, description, inputs and source URL, or the error that stopped it loading.',
    'Filter by `domain` (automation or script); an automation or script uses a blueprint by its `path`.',
    MASKED,
    PAGED,
    'Example: {"domain": "automation"} lists the automation blueprints.',
  ].join(' '),
  input: z.strictObject({ domain: scriptKind.optional().describe('automation or script; both when omitted.'), ...page }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run({ domain, ...paging }, ctx) {
    const listed = await Promise.all(
      (domain === undefined ? scriptKind.options : [domain]).map(async (d) =>
        Object.entries(await read<Record<string, BlueprintEntry>>(ctx, { type: 'blueprint/list', domain: d }))
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([path, entry]) => {
            if ('error' in entry) return { domain: d, path, error: entry.error };
            const { name, description, input, source_url } = entry.metadata;
            return { domain: d, path, name, description, inputs: input, source_url };
          }),
      ),
    );
    return text(pageOf('blueprints', listed.flat(), paging));
  },
});

/** A path under the domain's blueprint folder; no segment starts with a dot, so none climbs out of it. */
const blueprintPath = z
  .string()
  .regex(/^\w[\w.-]*(\/\w[\w.-]*)*$/, 'must be a relative path such as mine/porch_light.yaml')
  .transform((p) => (p.endsWith('.yaml') ? p : `${p}.yaml`));

const writeBlueprint = defineTool({
  title: 'Write blueprint',
  description: [
    "Creates, updates or deletes one automation or script blueprint from YAML the Caller supplies; it needs a config write of the blueprint's domain, and is admin-equivalent as that is.",
    "Name the blueprint by `domain` and `path` within that domain's blueprint folder, such as mine/porch_light.yaml; `.yaml` is added when left off.",
    'A create refuses a path that exists and an update replaces the whole file, so send the full YAML; importing a blueprint from a URL is not offered, so fetch the YAML first.',
    'YAML that carries **REDACTED** from a read is refused, so put the real value in its place first.',
    'Example: {"domain": "script", "action": "delete", "path": "mine/ping.yaml"}.',
  ].join(' '),
  input: z
    .strictObject({
      domain: scriptKind.describe('automation or script.'),
      action: z.enum(['create', 'update', 'delete']).describe('create, update or delete.'),
      path: blueprintPath.describe('The path within the domain blueprint folder, such as mine/porch_light.yaml.'),
      yaml: z.string().min(1).optional().describe('The whole blueprint YAML; omitted for delete.'),
    })
    .superRefine(({ action, yaml }, ctx) => {
      if (action !== 'delete' && yaml === undefined) ctx.addIssue({ code: 'custom', path: ['yaml'], message: `is required to ${action}` });
      if (action === 'delete' && yaml !== undefined) ctx.addIssue({ code: 'custom', path: ['yaml'], message: 'is not taken by delete' });
    }),
  annotations: { readOnlyHint: false, destructiveHint: true },
  kinds: ['automation', 'script'],
  decide: (change: BlueprintWrite, policy, caller) => ({
    ...decideBlueprintWrite(policy, caller, change),
    lacking: `config writes of ${change.domain}`,
    request: { domain: change.domain, action: change.action, path: change.path },
  }),
  async run({ domain, action, path, yaml }: BlueprintWrite, ctx) {
    const { allowed } = ctx;
    if (allowed?.write?.via !== 'websocket') throw new Error('blueprint write sent without an Allowed');
    if (redactedPath(yaml) !== undefined) {
      ctx.audit({ domain, action, path, decision: 'deny', reason: 'yaml carries a redacted value' });
      throw new ToolFailure('yaml carries a redacted value: put the real value in its place. Nothing was sent to Home Assistant.');
    }
    if (ctx.options.auditWrites) ctx.audit({ domain, action, path, decision: 'allow', grants: ctx.grants });
    const result = await send(ctx, allowed, allowed.write.command);
    if (ctx.options.auditWrites) ctx.audit({ domain, action, path, outcome: 'done' });
    return writeResult({ domain, action, path, result });
  },
});

const HELPER_LIST = '/api/config/config_entries/flow_handlers?type=helper';
/** The arguments each action takes; any other is refused. */
const FLOW_ARGS = { list: [], start: ['handler'], edit: ['entry_id'], step: ['flow_id', 'input'], abort: ['flow_id'], delete: ['entry_id'] } as const;

/** An entry's integration, by a lookup that runs nothing. */
async function entryDomain(ctx: Context, entryId: string): Promise<string> {
  try {
    return (await send<{ config_entry: { domain: string } }>(ctx, ctx.allowed, { type: 'config_entries/get_single', entry_id: entryId })).config_entry.domain;
  } catch (e) {
    if ((e as { code?: unknown }).code === 'not_found') throw new ToolFailure(`No entry ${entryId} exists; list the wizard helpers for their entry ids.`);
    throw e;
  }
}

/**
 * A flow's integration as HA reports it, and for an options flow the entry it edits. The progress list names a discovery
 * without running it; HA lists no other flow, and reading one re-runs its current step with no input.
 */
async function flowOf(ctx: Context, flowId: string): Promise<{ integration: string; entry_id?: string }> {
  const listed = (await send<{ flow_id: string; handler: string }[]>(ctx, ctx.allowed, { type: 'config_entries/flow/progress' })).find((f) => f.flow_id === flowId);
  const read = async (path: string) => (await rest(ctx, ctx.allowed, { method: 'GET', path: `${path}/${flowId}` })) as { handler: string } | undefined;
  const flow = listed ?? (await read('/api/config/config_entries/flow'));
  if (flow) return { integration: flow.handler };
  const options = await read('/api/config/config_entries/options/flow');
  if (!options) throw new ToolFailure(`No setup or options flow ${flowId} is in progress; start or edit one.`);
  return { integration: await entryDomain(ctx, options.handler), entry_id: options.handler };
}

const helperFlow = defineTool({
  title: 'Set up, edit or delete a wizard helper',
  description: [
    "Sets up, edits or deletes a wizard helper, such as a template sensor, a light group, a threshold or a switch shown as a light (switch_as_x), by driving Home Assistant's own setup and options forms one step at a time; this is admin-equivalent, because a template switch or button can run any action.",
    '`list` returns the helper integrations Home Assistant offers and the wizard helpers that exist, with their `entry_id`; `start` with a `handler` from that list begins a setup, and `edit` with an `entry_id` begins its options form; `step` with the `flow_id` either returned submits one step\'s `input`, answering a menu with {"next_step_id": "<option>"}; `abort` abandons the flow; `delete` with an `entry_id` removes the helper.',
    "Each step returns Home Assistant's answer as it stands: a `form` with its `data_schema` and any field `errors`, a `menu` with its `menu_options`, an `abort`, or a `create_entry` with the new entry in `result`; input Home Assistant rejects comes back with its field errors, and the same flow can be stepped again.",
    'Only integrations Home Assistant lists as helpers are served, so any other setup, edit or delete is refused, and so is step input that carries **REDACTED** from a read.',
    MASKED,
    'Example: {"action": "step", "flow_id": "9f2c4e1a7b3d4c8e9a1f2b3c4d5e6f70", "input": {"next_step_id": "sensor"}} picks a sensor from the template menu.',
  ].join(' '),
  input: z
    .strictObject({
      action: z.enum(['list', 'start', 'edit', 'step', 'abort', 'delete']).describe('list, start, edit, step, abort or delete.'),
      handler: slug.optional().describe('For start: a helper integration from list, such as template.'),
      flow_id: z.string().regex(FLOW_ID, 'must be the flow_id start or edit returned').optional().describe('For step and abort: the flow_id start or edit returned.'),
      entry_id: z.string().regex(FLOW_ID, 'must be an entry_id list returned').optional().describe('For edit and delete: a wizard helper\'s entry_id from list.'),
      input: z.record(z.string(), z.unknown()).optional().describe('For step: the form\'s fields, or {"next_step_id": "<option>"} for a menu.'),
    })
    .superRefine((args, ctx) => {
      const taken: readonly string[] = FLOW_ARGS[args.action];
      for (const key of ['handler', 'flow_id', 'input', 'entry_id'] as const) {
        if (taken.includes(key) && args[key] === undefined) ctx.addIssue({ code: 'custom', path: [key], message: `is required to ${args.action}` });
        if (!taken.includes(key) && args[key] !== undefined) ctx.addIssue({ code: 'custom', path: [key], message: `is not taken by ${args.action}` });
      }
    }),
  annotations: { readOnlyHint: false, destructiveHint: true },
  kinds: ['helper_entry'],
  // The Allowed here is for the lookups; the write is decided once HA has named the flow's integration.
  decide: ({ action, handler, flow_id, entry_id }, policy, caller) => ({
    ...decideConfigRead(policy, caller, 'helper_entry'),
    lacking: 'config writes of helper_entry',
    request: { kind: 'helper_entry', action, handler, flow_id, entry_id },
  }),
  async run({ action, handler, flow_id, entry_id, input }, ctx) {
    const lookup = (path: string) => rest(ctx, ctx.allowed, { method: 'GET', path });
    if (action === 'list') {
      const [handlers, entries] = await Promise.all([lookup(HELPER_LIST), lookup('/api/config/config_entries/entry?type=helper')]);
      const named = (entries as { entry_id: string; domain: string; title: string }[]).map(({ entry_id, domain, title }) => ({ entry_id, domain, title }));
      return writeResult(maskSecrets({ handlers: (handlers as string[]).sort(), entries: named }));
    }
    const names = { kind: 'helper_entry', action, flow_id, entry_id };
    const marked = redactedPath(input);
    if (marked !== undefined) {
      ctx.audit({ ...names, decision: 'deny', reason: 'input carries a redacted value' });
      throw new ToolFailure(`input carries a redacted value at ${marked}: put the real value in its place. Nothing was sent to Home Assistant.`);
    }
    const found = handler !== undefined ? { integration: handler } : entry_id !== undefined ? { integration: await entryDomain(ctx, entry_id), entry_id } : await flowOf(ctx, flow_id!);
    const { integration } = found;
    const options = found.entry_id !== undefined;
    const flow = (
      action === 'start' ? { action, handler } : action === 'step' ? { action, flow_id, input, options } : action === 'abort' ? { action, flow_id, options } : { action, entry_id }
    ) as HelperFlow;
    const decision = decideHelperFlow(ctx.policy, ctx.auth.caller, flow, integration, (await lookup(HELPER_LIST)) as string[]);
    const audit = (record: Record<string, unknown>) => ctx.audit({ ...names, handler: integration, entry_id: found.entry_id, ...record });
    if (!decision.allowed) {
      audit({ decision: 'deny', grants: [], reason: 'not a helper integration' });
      throw new ToolFailure(`Denied: Home Assistant does not list ${integration} as a helper integration, so this Caller may not drive its flows or delete its entries. Do not retry this call.`);
    }
    const { write } = decision.allowed;
    if (write.via !== 'rest') throw new Error('a helper flow is driven over REST');
    if (ctx.options.auditWrites) audit({ decision: 'allow', grants: decision.grants });
    const result = (await rest(ctx, decision.allowed, write.request)) as { flow_id?: string; type?: string; result?: { entry_id?: string } } | null;
    const created = result?.type === 'create_entry' ? result.result?.entry_id : undefined;
    if (ctx.options.auditWrites) audit({ outcome: 'done', flow_id: flow_id ?? result?.flow_id, entry_id: found.entry_id ?? created });
    return writeResult(maskSecrets(result));
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
  ha_get_statistics: getStatistics,
  ha_render_template: renderTemplate,
  ha_get_logs: getLogs,
  ha_get_dashboard: getDashboard,
  ha_list_blueprints: listBlueprints,
  ha_write_blueprint: writeBlueprint,
  ha_helper_flow: helperFlow,
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
  const holds = (name: ToolName) => {
    const { kinds } = TOOLS[name];
    return kinds === undefined ? grantsFor(policy, auth.caller, TOOL_KIND[name]).length > 0 : kinds.some((k) => writersOf(policy, auth.caller, k).length > 0);
  };
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
      const { kinds } = TOOLS[name];
      const lacking = kinds === undefined ? OPERATION_NAME[operation] : `config writes of ${kinds.join(' or ')}`;
      return failure(`Denied: this Caller holds no Grant for ${lacking}. Do not retry this call.`);
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
      audited({ decision: 'allow', grants: decided.grants, request: tool.auditable?.(args.data) ?? args.data });
    }
    try {
      const result = await tool.run(args.data, { ...decided, policy, auth, gate, audit: audited, options });
      // A read is refused whole rather than cut off, so the Caller never reasons over a truncated answer.
      if (READS.has(operation) && charsOf(result) > CHAR_CAP) {
        const narrowing = NARROWING[name];
        const over = `The response is over ${CHAR_CAP} characters, so nothing was returned`;
        return failure(narrowing === undefined ? `${over}, and this tool offers no narrower query.` : `${over}: narrow the query with ${narrowing}.`);
      }
      return server.projectCallToolResult(result, undefined);
    } catch (e) {
      if (e instanceof ToolFailure) return failure(e.message);
      throw e;
    }
  });
  return server;
}
