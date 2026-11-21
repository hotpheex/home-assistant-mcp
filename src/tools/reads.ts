import * as z from 'zod';
import { callable } from '../evaluator.ts';
import { dashboardPath } from '../ha.ts';
import { maskSecrets } from '../redaction.ts';
import { extract } from '../resolver.ts';
import {
  defineTool,
  entityId,
  epochSecondsToIso,
  MASKED,
  page,
  PAGED,
  pageOf,
  slug,
  text,
  timeWindow,
  ToolFailure,
  windowOf,
  type ToolRuntime,
} from './runtime.ts';

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

interface HaService {
  name?: string;
  description?: string;
  fields?: Record<string, unknown>;
  target?: unknown;
  response?: unknown;
}

async function registryNames(rt: ToolRuntime): Promise<Map<string, string[]>> {
  const [entities, devices, areas, labels] = await Promise.all([
    rt.read<RegistryEntity[]>({ type: 'config/entity_registry/list' }),
    rt.read<{ id: string; area_id: string | null }[]>({ type: 'config/device_registry/list' }),
    rt.read<{ area_id: string; name: string }[]>({ type: 'config/area_registry/list' }),
    rt.read<{ label_id: string; name: string }[]>({ type: 'config/label_registry/list' }),
  ]);
  // HA omits aliases from `config/entity_registry/list`; only `get_entries` includes them.
  const extended = await rt.read<Record<string, { aliases?: (string | null)[] } | null>>({
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

export const getStates = defineTool({
  operation: 'plain_read',
  title: 'Get entity states',
  description: [
    'Lists the current state of Home Assistant entities, sorted by entity_id, with each entity_id, friendly name and state.',
    'Filter by `domain` (such as `light`), by exact `state` (such as `on`), and by `query`, a case-insensitive substring of the entity_id, friendly name, aliases, or area and label names; filter by `area` or `label` id to get what a Home Assistant service call targeting that area or label acts on.',
    'Attributes are left out unless `full` is true; bearer tokens in camera, image and media_player attributes are always removed.',
    MASKED,
    PAGED,
    'Example: {"domain": "light", "query": "kitchen", "state": "on"} lists the kitchen lights that are on.',
  ].join(' '),
  narrowing: 'the domain, state, query, area or label filters, `full` off, or a smaller limit',
  instruction: 'Find entities and their entity_ids with ha_get_states, using its filters, before reading history or the logbook.',
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
  async run(args, rt) {
    const states = await rt.read<HaState[]>({ type: 'get_states' });
    const query = args.query?.toLowerCase();
    const names = query === undefined ? new Map<string, string[]>() : await registryNames(rt);
    const within = async (key: 'area_id' | 'label_id', id: string | undefined) =>
      id === undefined ? undefined : new Set(await extract((command) => rt.read(command), { [key]: [id] }));
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

async function notCurrent(rt: ToolRuntime, entityIds: string[]) {
  const current = new Set((await rt.read<HaState[]>({ type: 'get_states' })).map((s) => s.entity_id));
  const missing = entityIds.filter((id) => !current.has(id));
  return missing.length > 0 ? { not_current_entity_ids: missing } : {};
}

type HistoryRow = { s: string; lu: number; lc?: number };

function summarise(entity_id: string, rows: HistoryRow[], start: string, end: string) {
  const [from, to] = [Date.parse(start), Date.parse(end)];
  // HA stamps a synthetic first row at `start_time` for the pre-window state, which is not a change.
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

export const getHistory = defineTool({
  operation: 'plain_read',
  title: 'Get entity history',
  description: [
    "Lists the state changes of the given entities over a time window, without attributes, one row per change with its entity_id, state and last_changed time, sorted by entity_id and then time; each entity's first row is the state it already had at the window start, stamped with the start time.",
    'The window defaults to the last 24 hours; `start` and `end` take ISO 8601 times, and a `start` after `end` is refused; a named entity_id that is not a current entity is still read, because HA keeps the history of deleted and renamed entities, and is listed in `not_current_entity_ids`.',
    'With `summary` it returns one entry per entity instead: the number of changes after the window start, the state at the window start and the last state, and either the minimum, maximum and time-weighted mean of numeric states, with `skipped` counting the unknown, unavailable and other non-numeric states left out, or a count of each state.',
    MASKED,
    PAGED,
    'Example: {"entity_ids": ["sensor.kitchen_temperature"], "summary": true} summarises the kitchen temperature over the last day.',
  ].join(' '),
  narrowing: 'fewer entity_ids, a shorter window, `summary` or a smaller limit',
  input: z.strictObject({
    entity_ids: z.array(entityId).min(1).describe('The entities to read, such as ["light.kitchen"].'),
    ...timeWindow,
    summary: z.boolean().default(false).describe('One summary entry per entity instead of every change.'),
    ...page,
  }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run(args, rt) {
    const { start, end } = windowOf(args, 24);
    const [changes, missing] = await Promise.all([
      rt.read<Record<string, HistoryRow[]>>({
        type: 'history/history_during_period',
        start_time: start,
        end_time: end,
        entity_ids: args.entity_ids,
        no_attributes: true,
      }),
      notCurrent(rt, args.entity_ids),
    ]);
    const ids = Object.keys(changes).sort();
    const entries = args.summary
      ? ids.map((id) => summarise(id, changes[id]!, start, end))
      : ids.flatMap((id) => changes[id]!.map((c) => ({ entity_id: id, state: c.s, last_changed: epochSecondsToIso(c.lc ?? c.lu) })));
    return text({ start, end, ...missing, ...pageOf('history', entries, args) });
  },
});

export const getLogbook = defineTool({
  operation: 'plain_read',
  title: 'Get logbook',
  description: [
    'Lists Home Assistant logbook entries over a time window, oldest first: what changed or happened, when, and the context that caused it.',
    "The window defaults to the last hour; `start` and `end` take ISO 8601 times, and `entity_id` keeps only one entity's entries.",
    'A `start` after `end` is refused; an `entity_id` that is not a current entity is still read, because HA keeps the logbook of deleted and renamed entities, and is listed in `not_current_entity_ids`.',
    MASKED,
    PAGED,
    'Example: {"entity_id": "lock.front_door", "start": "2026-10-26T06:00:00Z"} shows the front door lock since 6 am UTC.',
  ].join(' '),
  narrowing: 'an entity_id, a shorter window or a smaller limit',
  input: z.strictObject({
    ...timeWindow,
    entity_id: entityId.optional().describe("Only this entity's entries."),
    ...page,
  }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run(args, rt) {
    const { start, end } = windowOf(args, 1);
    const [entries, missing] = await Promise.all([
      rt.read<{ when: number }[]>({
        type: 'logbook/get_events',
        start_time: start,
        end_time: end,
        ...(args.entity_id !== undefined && { entity_ids: [args.entity_id] }),
      }),
      args.entity_id === undefined ? {} : notCurrent(rt, [args.entity_id]),
    ]);
    return text({ start, end, ...missing, ...pageOf('entries', entries.map((e) => ({ ...e, when: epochSecondsToIso(e.when) })), args) });
  },
});

const mentions = (value: unknown, query: string): boolean =>
  typeof value === 'string'
    ? value.toLowerCase().includes(query)
    : typeof value === 'object' && value !== null && Object.values(value).some((v) => mentions(v, query));

export const getRegistry = defineTool({
  operation: 'plain_read',
  title: 'Get registry',
  description: [
    'Lists the entries of one Home Assistant registry, in registry order: `entity`, `device`, `area`, `label` or `floor`.',
    'Entries are returned as Home Assistant stores them, with ids, names and the area, floor, device and label ids that link them.',
    "`query` keeps entries with any text value that contains it, case-insensitively: an id, a name or an alias, and nested values too, such as a device's MAC address or identifiers; fixed values such as `disabled_by` match too, so \"user\" also finds entries a user disabled.",
    MASKED,
    PAGED,
    'Example: {"registry": "area", "query": "kitchen"} finds the kitchen area and its floor_id.',
  ].join(' '),
  narrowing: 'a query or a smaller limit',
  input: z.strictObject({
    registry: z.enum(['entity', 'device', 'area', 'label', 'floor']).describe('The registry to list.'),
    query: z.string().min(1).optional().describe('Case-insensitive substring of any text value in an entry, nested ones included.'),
    ...page,
  }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run(args, rt) {
    const entries = await rt.read<Record<string, unknown>[]>({ type: `config/${args.registry}_registry/list` });
    const query = args.query?.toLowerCase();
    return text(pageOf('entries', query === undefined ? entries : entries.filter((e) => mentions(e, query)), args));
  },
});

export const listServices = defineTool({
  operation: 'plain_read',
  title: 'List services',
  description: [
    'Lists every service Home Assistant offers, sorted by name, each with its fields, whether it takes a target, whether it returns a response, and whether this Caller may call it (`callable`).',
    'A service marked callable may still be refused for a particular target that this Caller may not act on.',
    'Filter by `domain` (such as `light`).',
    MASKED,
    PAGED,
    'Example: {"domain": "light"} lists the light services.',
  ].join(' '),
  narrowing: 'a domain or a smaller limit',
  input: z.strictObject({
    domain: slug.optional().describe('Service domain, such as light.'),
    ...page,
  }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run(args, rt) {
    const all = await rt.read<Record<string, Record<string, HaService>>>({ type: 'get_services' });
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
        callable: callable(rt.policy, rt.auth.caller, service, d.target !== undefined),
      }));
    return text(pageOf('services', services, args));
  },
});

const STATISTIC_TYPES = ['min', 'max', 'mean', 'sum', 'state', 'change'] as const;
type StatisticRow = { start: number; end: number } & Record<string, unknown>;

export const getStatistics = defineTool({
  operation: 'plain_read',
  title: 'Get long-term statistics',
  description: [
    "Without `statistic_ids`, lists the long-term statistics Home Assistant keeps, sorted by statistic_id, with each one's name, unit and source; `query` keeps those whose statistic_id or name contains it, case-insensitively.",
    'With `statistic_ids`, returns one row per statistic and `period` (`5minute`, `hour`, `day`, `week` or `month`; default `hour`), sorted by statistic_id and then time, with its start and end and the chosen `types` (`min`, `max`, `mean`, `sum`, `state` and `change`; default all), null where a statistic does not keep that type.',
    'The window defaults to the last 7 days; `start` and `end` take ISO 8601 times, and a `start` after `end` is refused.',
    MASKED,
    PAGED,
    'Example: {"statistic_ids": ["sensor.grid_energy"], "period": "month", "types": ["change"], "start": "2026-01-01T00:00:00Z"} gives the energy used each month this year.',
  ].join(' '),
  narrowing: 'a query, fewer statistic_ids, a shorter window, a longer period, fewer types or a smaller limit',
  input: z
    .strictObject({
      query: z.string().min(1).optional().describe('Listing only: case-insensitive substring of the statistic_id or name.'),
      statistic_ids: z.array(z.string().min(1)).min(1).optional().describe('The statistics to read, such as ["sensor.grid_energy"]; leave out to list them.'),
      period: z.enum(['5minute', 'hour', 'day', 'week', 'month']).default('hour').describe('The length of each row.'),
      types: z.array(z.enum(STATISTIC_TYPES)).min(1).default([...STATISTIC_TYPES]).describe('The values each row carries.'),
      ...timeWindow,
      ...page,
    })
    .superRefine(({ query, statistic_ids, start, end }, ctx) => {
      if (statistic_ids !== undefined && query !== undefined) ctx.addIssue({ code: 'custom', path: ['query'], message: 'is taken only when listing, without statistic_ids' });
      for (const [key, value] of Object.entries({ start, end })) {
        if (statistic_ids === undefined && value !== undefined) ctx.addIssue({ code: 'custom', path: [key], message: 'is taken only with statistic_ids' });
      }
    }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run(args, rt) {
    if (args.statistic_ids === undefined) {
      const query = args.query?.toLowerCase();
      const ids = (await rt.read<{ statistic_id: string; name: string | null }[]>({ type: 'recorder/list_statistic_ids' }))
        .filter((s) => query === undefined || [s.statistic_id, s.name ?? ''].some((v) => v.toLowerCase().includes(query)))
        .sort((a, b) => a.statistic_id.localeCompare(b.statistic_id));
      return text(pageOf('statistic_ids', ids, args));
    }
    const { start, end } = windowOf(args, 7 * 24);
    const periods = await rt.read<Record<string, StatisticRow[]>>({
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

export const renderTemplate = defineTool({
  operation: 'plain_read',
  title: 'Render template',
  description: [
    "Renders one Home Assistant template, such as one meant for an automation, and returns its `result` and the `listeners` (entities, domains and time) that would render it again, or Home Assistant's template error.",
    "Undefined names are errors, as in Home Assistant's template editor, so give the values of the template's own names in `variables`.",
    'A render that takes longer than `timeout` seconds (default 5, at most 15) fails.',
    MASKED,
    'Example: {"template": "{{ states(\'sensor.kitchen_temperature\') | float > 20 }}"} tells whether the kitchen is above 20 degrees.',
  ].join(' '),
  narrowing: 'a template that renders less',
  input: z.strictObject({
    template: z.string().min(1).describe("The template, such as {{ states('light.kitchen') }}."),
    variables: z.record(z.string(), z.unknown()).optional().describe('Values for names the template uses.'),
    timeout: z.number().positive().max(15).default(5).describe('Seconds the render may take, at most 15.'),
  }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  auditable: ({ timeout }) => ({ timeout }),
  async run(args, rt) {
    // HA emits a warning event before the result without `strict: true`, and drops render errors without `report_errors: true`.
    const command = {
      type: 'render_template',
      template: args.template,
      ...(args.variables && { variables: args.variables }),
      timeout: args.timeout,
      strict: true,
      report_errors: true,
    };
    const event = await rt.subscribeOnce<{ error?: string }>(command);
    if (event.error !== undefined) throw new ToolFailure(`Home Assistant could not render the template: ${event.error}`);
    return text(maskSecrets(event));
  },
});

export const getDashboard = defineTool({
  operation: 'plain_read',
  title: 'Get dashboard',
  description: [
    'Without `dashboard`, lists the dashboards stored in Home Assistant, each with its URL path, title and sidebar settings.',
    "With `dashboard`, returns that dashboard's stored layout, or with `view` only that view, named by its index from 0 or its path; `lovelace` names the default dashboard.",
    'A dashboard whose layout Home Assistant generates has no stored layout, so reading it is refused.',
    MASKED,
    'Example: {"dashboard": "kitchen-wall", "view": 0}.',
  ].join(' '),
  narrowing: 'a `view`, by its index or path',
  input: z
    .strictObject({
      dashboard: z.string().min(1).optional().describe('A dashboard URL path, such as kitchen-wall; lovelace is the default dashboard.'),
      view: z.union([z.number().int().min(0), z.string().min(1)]).optional().describe('One view of the dashboard: its index from 0, or its path.'),
    })
    .superRefine(({ dashboard, view }, ctx) => {
      if (dashboard === undefined && view !== undefined) ctx.addIssue({ code: 'custom', path: ['view'], message: 'is taken only with dashboard' });
    }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run({ dashboard, view }, rt) {
    if (dashboard === undefined) return text({ dashboards: await rt.read({ type: 'lovelace/dashboards/list' }) });
    const config = await rt.read<{ views?: { path?: string }[] }>({ type: 'lovelace/config', ...dashboardPath(dashboard) });
    if (view === undefined) return text({ dashboard, config });
    const views = config.views ?? [];
    const found = typeof view === 'number' ? views[view] : views.find((v) => v.path === view);
    if (found) return text({ dashboard, view: found });
    const paths = views.flatMap((v) => v.path ?? []);
    throw new ToolFailure(
      `Dashboard ${dashboard} has no view ${view}: it has ${views.length} views, by index from 0${paths.length > 0 ? ` or by path ${paths.join(', ')}` : ''}.`,
    );
  },
});
