import { randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { WebSocketServer } from 'ws';
import { parse } from 'yaml';

export interface FakeState {
  entity_id: string;
  state: string;
  attributes: Record<string, unknown>;
}

export interface FakeEntity {
  entity_id: string;
  name?: string | null;
  device_id?: string | null;
  area_id?: string | null;
  labels?: string[];
  hidden_by?: string | null;
  disabled_by?: string | null;
  entity_category?: 'config' | 'diagnostic' | null;
  platform?: string;
  unique_id?: string;
  aliases?: string[];
}
export interface ServiceDescription {
  name?: string;
  fields?: Record<string, unknown>;
  target?: Record<string, unknown>;
  response?: { optional: boolean };
}
export type FakeEntry = Record<string, unknown>;
export interface FakeChange {
  entity_id: string;
  state: string;
  when: string;
}
export interface FakeLogEntry {
  when: string;
  entity_id?: string;
  name?: string;
  state?: string;
  message?: string;
}

export interface FakeHaOptions {
  version?: string;
  users: Record<string, { is_admin: boolean }>;
  states?: FakeState[];
  services?: Record<string, Record<string, ServiceDescription>>;
  responses?: Record<string, unknown>;
  entities?: FakeEntity[];
  devices?: FakeEntry[];
  areas?: FakeEntry[];
  labels?: FakeEntry[];
  floors?: FakeEntry[];
  history?: FakeChange[];
  logbook?: FakeLogEntry[];
  configs?: Record<string, Record<string, unknown>>;
  traces?: FakeTrace[];
  helpers?: Record<string, Record<string, unknown>[]>;
  statistics?: FakeStatistic[];
  templates?: Record<string, FakeTemplate>;
  systemLog?: Record<string, unknown>[];
  zones?: Record<string, unknown>[];
  blueprints?: Record<string, Record<string, Record<string, unknown>>>;
  dashboards?: Record<string, unknown>[];
  layouts?: Record<string, Record<string, unknown>>;
  entries?: FakeConfigEntry[];
  flows?: FakeFlow[];
  optionsFlows?: FakeFlow[];
}

export interface FakeConfigEntry {
  entry_id: string;
  domain: string;
  title: string;
  source: string;
  options: Record<string, unknown>;
}
export interface FakeFlow {
  flow_id: string;
  handler: string;
  source: string;
  step_id: string;
}
const HELPER_HANDLERS = ['derivative', 'filter', 'generic_hygrostat', 'generic_thermostat', 'group', 'history_stats', 'integration', 'min_max', 'mold_indicator', 'otp', 'random', 'statistics', 'switch_as_x', 'template', 'threshold', 'tod', 'trend', 'utility_meter'];
type FlowStep = { menu: string[] } | { fields: Record<string, boolean>; title: string };
const FLOW_STEPS: Record<string, Record<string, FlowStep>> = {
  template: {
    user: { menu: ['alarm_control_panel', 'binary_sensor', 'button', 'sensor', 'switch'] },
    sensor: { fields: { name: true, state: true, unit_of_measurement: false }, title: 'name' },
  },
  switch_as_x: { user: { fields: { entity_id: true, invert: false, target_domain: true }, title: 'entity_id' } },
  hue: { user: { fields: { host: true }, title: 'host' } },
};
const OPTIONS_FORMS: Record<string, { step_id: string; fields: Record<string, boolean> }> = {
  template: { step_id: 'sensor', fields: { state: true, unit_of_measurement: false } },
  hue: { step_id: 'init', fields: { allow_hue_groups: false } },
};

const HELPER_DOMAINS = ['input_boolean', 'input_number', 'input_select', 'input_text', 'input_datetime', 'input_button', 'counter', 'timer', 'schedule'];
const REGISTRY_UPDATE_KEYS = ['aliases', 'area_id', 'categories', 'device_class', 'icon', 'labels', 'name', 'new_entity_id', 'disabled_by', 'hidden_by', 'options_domain', 'options'];
const DAYS = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'];
const HELPER_SCHEMAS: Record<string, { required: string[]; defaults: Record<string, unknown>; optional: string[] }> = {
  input_boolean: { required: ['name'], defaults: {}, optional: ['initial'] },
  input_number: { required: ['name', 'min', 'max'], defaults: { step: 1, mode: 'slider' }, optional: ['initial', 'unit_of_measurement'] },
  input_select: { required: ['name', 'options'], defaults: {}, optional: ['initial'] },
  input_text: { required: ['name'], defaults: { min: 0, max: 100, mode: 'text' }, optional: ['initial', 'unit_of_measurement', 'pattern'] },
  input_datetime: { required: ['name'], defaults: { has_date: false, has_time: false }, optional: ['initial'] },
  input_button: { required: ['name'], defaults: {}, optional: [] },
  counter: { required: ['name'], defaults: { initial: 0, maximum: null, minimum: null, restore: true, step: 1 }, optional: [] },
  timer: { required: ['name'], defaults: { duration: '0:00:00', restore: false }, optional: [] },
  schedule: { required: ['name'], defaults: Object.fromEntries(DAYS.map((d) => [d, []])), optional: [] },
};
const REQUIRED_KEYS: Record<string, string[]> = { automation: ['triggers', 'actions'], script: ['sequence'], scene: ['name', 'entities'] };

export interface FakeStatistic {
  statistic_id: string;
  name: string | null;
  source: string;
  unit_of_measurement: string | null;
  has_sum: boolean;
  mean_type: number;
  periods: Partial<Record<'5minute' | 'hour' | 'day' | 'week' | 'month', ({ start: string } & Partial<Record<'min' | 'max' | 'mean' | 'sum' | 'state' | 'change', number>>)[]>>;
}

export interface FakeTrace extends Record<string, unknown> {
  domain: 'automation' | 'script';
  item_id: string;
  run_id: string;
  timestamp: { start: string; finish: string };
}
const TRACE_SECTIONS = ['trace', 'config', 'blueprint_inputs', 'context'];

export interface FakeTemplate {
  result?: unknown;
  variable?: string;
  compileError?: string;
  renderError?: string;
  seconds?: number;
}
const pyFloat = (n: number) => (Number.isInteger(n) ? n.toFixed(1) : String(n));

export interface Received {
  token: string;
  message: { type: string; id?: number } & Record<string, unknown>;
}

class HaError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}
const haError = (code: string, message: string): never => {
  throw new HaError(code, message);
};

type Target = Partial<Record<'entity_id' | 'device_id' | 'area_id' | 'floor_id' | 'label_id', string | string[]>>;
type Entity = Required<Omit<FakeEntity, 'name' | 'aliases' | 'platform' | 'unique_id'>>;
type Device = { id: string; area_id: string | null; labels: string[]; parent_device_id: string | null };
export type Registry = {
  entities: Entity[];
  devices: Device[];
  areas: { area_id: string; floor_id: string | null; labels: string[] }[];
  floors: { floor_id: string }[];
  labels: { label_id: string }[];
};

function registryOf(o: Pick<FakeHaOptions, 'entities' | 'devices' | 'areas' | 'floors' | 'labels'>): Registry {
  return {
    entities: (o.entities ?? []).map((e) => ({ device_id: null, area_id: null, labels: [], hidden_by: null, disabled_by: null, entity_category: null, ...e })),
    devices: (o.devices ?? []).map((d) => ({ area_id: null, labels: [], parent_device_id: null, ...d }) as unknown as Device),
    areas: (o.areas ?? []).map((a) => ({ floor_id: null, labels: [], ...a }) as unknown as Registry['areas'][number]),
    floors: (o.floors ?? []) as Registry['floors'],
    labels: (o.labels ?? []) as Registry['labels'],
  };
}

const ids = (v: string | string[] | undefined): Set<string> => (v === undefined || v === 'none' ? new Set() : new Set(Array.isArray(v) ? v : [v]));

function extractFromTarget(h: Registry, target: Target, primaryEntitiesOnly = true) {
  const t ={ e: ids(target.entity_id), d: ids(target.device_id), a: ids(target.area_id), f: ids(target.floor_id), l: ids(target.label_id) };
  for (const e of t.e) if (!/^[a-z0-9_]+\.[a-z0-9_]+$/.test(e)) haError('invalid_format', `Entity ID ${e} is an invalid entity ID`);
  const referenced = new Set(t.e);
  const refDevices = new Set<string>();
  const refAreas = new Set<string>();
  const missing = { devices: new Set<string>(), areas: new Set<string>(), floors: new Set<string>(), labels: new Set<string>() };
  const out = () => ({
    referenced_entities: [...referenced],
    referenced_devices: [...refDevices],
    referenced_areas: [...refAreas],
    missing_devices: [...missing.devices],
    missing_areas: [...missing.areas],
    missing_floors: [...missing.floors],
    missing_labels: [...missing.labels],
  });
  if (!t.d.size && !t.a.size && !t.f.size && !t.l.size) return out();
  const dev = new Map(h.devices.map((d) => [d.id, d]));
  const addDevice = (id: string) => {
    refDevices.add(id);
    for (const c of h.devices) if (c.parent_device_id === id) refDevices.add(c.id);
  };
  for (const f of t.f) if (!h.floors.some((x) => x.floor_id === f)) missing.floors.add(f);
  for (const a of t.a) if (!h.areas.some((x) => x.area_id === a)) missing.areas.add(a);
  for (const d of t.d) {
    if (dev.has(d)) addDevice(d);
    else {
      missing.devices.add(d);
      refDevices.add(d);
    }
  }
  for (const l of t.l) {
    if (!h.labels.some((x) => x.label_id === l)) missing.labels.add(l);
    for (const e of h.entities) if (e.labels.includes(l) && e.hidden_by === null) referenced.add(e.entity_id);
    for (const d of h.devices) if (d.labels.includes(l)) addDevice(d.id);
    for (const a of h.areas) if (a.labels.includes(l)) refAreas.add(a.area_id);
  }
  for (const a of h.areas) if (a.floor_id !== null && t.f.has(a.floor_id)) refAreas.add(a.area_id);
  for (const a of t.a) refAreas.add(a);
  if (!refAreas.size && !refDevices.size) return out();
  const include = (e: Entity) => e.hidden_by === null && (!primaryEntitiesOnly || e.entity_category === null);
  for (const d of refDevices) for (const e of h.entities) if (e.device_id === d && e.disabled_by === null && include(e)) referenced.add(e.entity_id);
  const effectiveArea = (d: Device) => d.area_id ?? (d.parent_device_id ? (dev.get(d.parent_device_id)?.area_id ?? null) : null);
  const areaDevices = new Set(
    h.devices
      .filter((d) => {
        const a = effectiveArea(d);
        return a !== null && refAreas.has(a);
      })
      .map((d) => d.id),
  );
  for (const d of areaDevices) refDevices.add(d);
  for (const e of h.entities) if (e.area_id !== null && refAreas.has(e.area_id) && include(e)) referenced.add(e.entity_id);
  for (const e of h.entities) {
    if (e.device_id !== null && areaDevices.has(e.device_id) && e.disabled_by === null && include(e) && !e.area_id) referenced.add(e.entity_id);
  }
  return out();
}

const isoNow = () => new Date().toISOString();
const seconds = (iso: string) => Date.parse(iso) / 1000;
type Message = Received['message'];
const inWindow = (when: string, msg: Message) =>
  Date.parse(when) >= Date.parse(msg.start_time as string) &&
  Date.parse(when) <= (msg.end_time === undefined ? Date.now() : Date.parse(msg.end_time as string));

export async function startFakeHa(options: FakeHaOptions) {
  let version = options.version ?? '2026.10.4';
  const received: Received[] = [];
  let contexts = 0;
  const drop = new Set<string>();
  const stall = new Set<string>();
  let down = false;
  let hung = false;
  let refused = 0;
  const entities = structuredClone(options.entities ?? []);
  const entityEntry = (e: FakeEntity) => {
    const entry: Partial<FakeEntity> = { name: null, device_id: null, area_id: null, labels: [], hidden_by: null, disabled_by: null, entity_category: null, ...e };
    delete entry.aliases;
    return entry;
  };
  interface Connection {
    emit(event: unknown): void;
    subscriptions: Set<number>;
  }
  type Handler = (token: string, msg: Message, conn: Connection) => unknown;
  const adminOnly = (handler: Handler): Handler => (token, msg, conn) =>
    options.users[token]?.is_admin ? handler(token, msg, conn) : haError('unauthorized', 'Unauthorized');
  const configs = structuredClone(options.configs ?? {});
  const entries = structuredClone(options.entries ?? []);
  const flows = structuredClone(options.flows ?? []);
  const optionsFlows = structuredClone(options.optionsFlows ?? []);
  const helpers = structuredClone(options.helpers ?? {});
  const zones = structuredClone(options.zones ?? []);
  const blueprints = structuredClone(options.blueprints ?? {});
  const dashboards = structuredClone(options.dashboards ?? []);
  const layouts = structuredClone(options.layouts ?? {});
  const layoutKey = (msg: Message) =>
    msg.url_path === undefined || msg.url_path === null
      ? 'lovelace'
      : dashboards.some((d) => d.url_path === msg.url_path)
        ? (msg.url_path as string)
        : haError('config_not_found', `Unknown config specified: ${msg.url_path as string}`);
  const configOf = adminOnly((_, msg) => {
    const config = configs[msg.entity_id as string];
    return config && (msg.entity_id as string).startsWith(`${msg.type.split('/')[0]}.`) ? { config } : haError('not_found', 'Entity not found');
  });
  const handlers: Record<string, Handler> = {
    supported_features: () => null,
    unsubscribe_events: (_, msg, conn) => (conn.subscriptions.delete(msg.subscription as number) ? null : haError('not_found', 'Subscription not found.')),
    get_states: () =>
      (options.states ?? []).map((s) => ({
        ...s,
        last_changed: isoNow(),
        last_reported: isoNow(),
        last_updated: isoNow(),
        context: { id: '01FAKE', parent_id: null, user_id: null },
      })),
    'auth/current_user': (token) => ({
      id: token,
      name: 'fake',
      is_owner: false,
      is_admin: options.users[token]?.is_admin ?? false,
      credentials: [],
      mfa_modules: [],
    }),
    get_services: () => options.services ?? {},
    extract_from_target: (_token, msg) => extractFromTarget(registryOf(options), msg.target as Target, (msg.primary_entities_only as boolean | undefined) ?? true),
    call_service: (token, msg) => {
      const name = `${String(msg.domain)}.${String(msg.service)}`;
      const description = options.services?.[String(msg.domain)]?.[String(msg.service)];
      if (!description) return haError('not_found', `Service ${name} not found.`);
      if (msg.return_response === true && !description.response) {
        haError('service_validation_error', "Validation error: An action which does not return responses can't be called with return_response=True");
      }
      if (msg.return_response !== true && description.response?.optional === false) {
        haError('service_validation_error', 'Validation error: The action requires responses and must be called with return_response=True');
      }
      const context = { id: `ctx-${++contexts}`, parent_id: null, user_id: token };
      return msg.return_response === true ? { context, response: options.responses?.[name] ?? {} } : { context };
    },
    'config/entity_registry/list': () => entities.map(entityEntry),
    'config/entity_registry/get_entries': (_, msg) =>
      Object.fromEntries(
        (msg.entity_ids as string[]).map((id) => {
          const e = entities.find((x) => x.entity_id === id);
          return [id, e ? { ...entityEntry(e), aliases: e.aliases ?? [] } : null];
        }),
      ),
    'config/entity_registry/update': adminOnly((_, msg) => {
      const entity = entities.find((e) => e.entity_id === msg.entity_id) ?? haError('not_found', 'Entity not found');
      const changes = Object.fromEntries(Object.entries(msg).filter(([k]) => !['id', 'type', 'entity_id'].includes(k)));
      const extra = Object.keys(changes).find((k) => !REGISTRY_UPDATE_KEYS.includes(k));
      if (extra) haError('invalid_format', `extra keys not allowed @ data['${extra}']`);
      const { new_entity_id, ...fields } = changes;
      Object.assign(entity, fields, typeof new_entity_id === 'string' && { entity_id: new_entity_id });
      return { entity_entry: { ...entityEntry(entity), aliases: entity.aliases ?? [] } };
    }),
    'config/device_registry/list': () => options.devices ?? [],
    'config/area_registry/list': () => options.areas ?? [],
    'config/label_registry/list': () => options.labels ?? [],
    'config/floor_registry/list': () => options.floors ?? [],
    // HA parses times to the microsecond, so the start row keeps any digits past the millisecond.
    'history/history_during_period': (_, msg) => {
      const out: Record<string, { s: string; lu: number }[]> = {};
      const start = Date.parse(msg.start_time as string);
      for (const id of msg.entity_ids as string[]) {
        const changes = (options.history ?? []).filter((c) => c.entity_id === id);
        const before = changes.filter((c) => Date.parse(c.when) <= start).at(-1);
        const rows = [
          ...(before ? [{ s: before.state, lu: start / 1000 + Number(`0.000${/\.\d{3}(\d{1,3})/.exec(msg.start_time as string)?.[1] ?? ''}`) }] : []),
          ...changes.filter((c) => Date.parse(c.when) > start && inWindow(c.when, msg)).map((c) => ({ s: c.state, lu: seconds(c.when) })),
        ];
        if (rows.length > 0) out[id] = rows;
      }
      return out;
    },
    'automation/config': configOf,
    'script/config': configOf,
    'trace/list': adminOnly((_, msg) =>
      (options.traces ?? [])
        .filter((tr) => tr.domain === msg.domain && (msg.item_id === undefined || tr.item_id === msg.item_id))
        .map((tr) => Object.fromEntries(Object.entries(tr).filter(([k]) => !TRACE_SECTIONS.includes(k)))),
    ),
    'trace/get': adminOnly(
      (_, msg) =>
        options.traces?.find((tr) => tr.domain === msg.domain && tr.item_id === msg.item_id && tr.run_id === msg.run_id) ??
        haError('not_found', 'The trace could not be found'),
    ),
    'config_entries/flow/progress': adminOnly(() =>
      flows.filter((f) => !['user', 'reconfigure'].includes(f.source)).map((f) => ({ flow_id: f.flow_id, handler: f.handler, step_id: f.step_id, context: { source: f.source } })),
    ),
    'config_entries/get_single': adminOnly((_, msg) => {
      const entry = entries.find((e) => e.entry_id === msg.entry_id);
      return entry ? { config_entry: served(entry) } : haError('not_found', 'Config entry not found');
    }),
    'logbook/get_events': (_, msg) =>
      (options.logbook ?? [])
        .filter((e) => inWindow(e.when, msg) && (msg.entity_ids === undefined || (msg.entity_ids as string[]).includes(e.entity_id ?? '')))
        .map((e) => ({ ...e, when: seconds(e.when) })),
    'recorder/list_statistic_ids': () =>
      (options.statistics ?? []).map(({ statistic_id, name, source, unit_of_measurement, has_sum, mean_type }) => ({
        statistic_id,
        display_unit_of_measurement: unit_of_measurement,
        has_mean: mean_type === 1,
        mean_type,
        has_sum,
        name,
        source,
        statistics_unit_of_measurement: unit_of_measurement,
        unit_class: null,
      })),
    'recorder/statistics_during_period': (_, msg) => {
      const period = msg.period as keyof FakeStatistic['periods'];
      const ms = { '5minute': 300_000, hour: 3_600_000, day: 86_400_000, week: 604_800_000, month: 2_592_000_000 }[period];
      if (ms === undefined || !Array.isArray(msg.statistic_ids) || msg.statistic_ids.length === 0) return haError('invalid_format', 'Invalid statistics request');
      const types = msg.types as string[];
      const [from, to] = [Date.parse(msg.start_time as string), msg.end_time === undefined ? Date.now() : Date.parse(msg.end_time as string)];
      const out: Record<string, Record<string, number | null>[]> = {};
      for (const s of (options.statistics ?? []).filter((x) => (msg.statistic_ids as string[]).includes(x.statistic_id))) {
        const rows = (s.periods[period] ?? [])
          .filter((r) => from <= Date.parse(r.start) && Date.parse(r.start) < to)
          .map((r) => ({ start: Date.parse(r.start), end: Date.parse(r.start) + ms, ...Object.fromEntries(types.map((k) => [k, new Map(Object.entries(r)).get(k) ?? null])) }));
        if (rows.length > 0) out[s.statistic_id] = rows;
      }
      return out;
    },
    render_template: (_, msg, conn) => {
      const template = typeof msg.template === 'string' ? msg.template : haError('invalid_format', "required key not provided @ data['template']");
      const render = options.templates?.[template] ?? { result: template };
      const timeout = msg.timeout === undefined ? 0 : Number(msg.timeout);
      if (timeout && (render.seconds ?? 0) > timeout) haError('template_error', `Exceeded maximum execution time of ${pyFloat(timeout)}s`);
      if (render.compileError !== undefined) haError('template_error', render.compileError);
      const report = msg.report_errors === true;
      const missing = render.variable !== undefined && !Object.hasOwn((msg.variables as Record<string, unknown> | undefined) ?? {}, render.variable);
      const renderError = render.renderError ?? (missing && msg.strict === true ? `UndefinedError: '${render.variable}' is undefined` : undefined);
      if (renderError !== undefined) {
        if (report) conn.emit({ error: renderError, level: 'ERROR' });
        return null;
      }
      if (missing && report) conn.emit({ error: `'${render.variable}' is undefined`, level: 'WARNING' });
      const entities = [...template.matchAll(/states\(['"]([\w.]+)['"]\)/g)].map((m) => m[1]);
      conn.emit({ result: missing ? '' : render.result, listeners: { all: false, domains: [], entities, time: false } });
      return null;
    },
    'system_log/list': adminOnly(() => [...(options.systemLog ?? [])].reverse()),
    'blueprint/list': adminOnly((_, msg) => blueprints[msg.domain as string] ?? {}),
    'blueprint/save': adminOnly((_, msg) => {
      const domain = msg.domain as string;
      const metadata = (parse(msg.yaml as string) as { blueprint?: { domain?: string } } | null)?.blueprint;
      if (metadata?.domain !== domain) haError('invalid_format', `Invalid blueprint: Found incorrect blueprint type ${metadata?.domain}, expected ${domain}`);
      const path = (msg.path as string).endsWith('.yaml') ? (msg.path as string) : `${msg.path as string}.yaml`;
      const stored = (blueprints[domain] ??= {});
      const exists = path in stored;
      if (exists && msg.allow_override !== true) haError('already_exists', 'File already exists');
      stored[path] = { metadata };
      return { overrides_existing: exists };
    }),
    'blueprint/delete': adminOnly((_, msg) => {
      const stored = blueprints[msg.domain as string] ?? {};
      const path = msg.path as string;
      if (!(path in stored)) haError('unknown_error', `[Errno 2] No such file or directory: '${path}'`);
      delete stored[path];
      return null;
    }),
    'lovelace/dashboards/list': () => dashboards,
    'lovelace/config': (_, msg) => layouts[layoutKey(msg)] ?? haError('config_not_found', 'No config found.'),
    'lovelace/config/save': adminOnly((_, msg) => {
      layouts[layoutKey(msg)] = msg.config as Record<string, unknown>;
      return null;
    }),
    'lovelace/dashboards/create': adminOnly((_, msg) => {
      const fields = Object.fromEntries(Object.entries(msg).filter(([k]) => !['id', 'type', 'allow_single_word'].includes(k)));
      const path = fields.url_path as string;
      if (msg.allow_single_word !== true && !path.includes('-')) haError('invalid_format', 'Url path needs to contain a hyphen (-)');
      if (path === 'lovelace' || dashboards.some((d) => d.url_path === path)) haError('home_assistant_error', `The URL "${path}" is already in use`);
      const extra = Object.keys(fields).find((k) => !['url_path', 'title', 'icon', 'show_in_sidebar', 'require_admin', 'mode'].includes(k));
      if (extra) haError('invalid_format', `extra keys not allowed @ data['${extra}']`);
      if (typeof fields.title !== 'string') haError('invalid_format', "required key not provided @ data['title']");
      const base = path.replace(/[^a-z0-9]+/g, '_');
      let id = base;
      for (let n = 2; dashboards.some((d) => d.id === id); n++) id = `${base}_${n}`;
      const item = { id, show_in_sidebar: true, require_admin: false, mode: 'storage', ...fields };
      dashboards.push(item);
      return item;
    }),
    'lovelace/dashboards/delete': adminOnly((_, msg) => {
      const item = dashboards.find((d) => d.id === msg.dashboard_id) ?? haError('not_found', `Unable to find dashboard_id ${String(msg.dashboard_id)}`);
      dashboards.splice(dashboards.indexOf(item), 1);
      delete layouts[String(item.url_path)];
      return null;
    }),
  };
  for (const domain of HELPER_DOMAINS) {
    const items = () => (helpers[domain] ??= []);
    const key = `${domain}_id`;
    const find = (msg: Message) => items().find((i) => i.id === msg[key]) ?? haError('not_found', `Unable to find ${key} ${String(msg[key])}`);
    const fieldsOf = (msg: Message) => Object.fromEntries(Object.entries(msg).filter(([k]) => !['id', 'type', key].includes(k)));
    handlers[`${domain}/list`] = () => items();
    handlers[`${domain}/create`] = adminOnly((_, msg) => {
      const item = { id: String(msg.name).toLowerCase().replace(/[^a-z0-9]+/g, '_'), ...fieldsOf(msg) };
      items().push(item);
      return item;
    });
    handlers[`${domain}/update`] = adminOnly((_, msg) => {
      const item = find(msg);
      const fields = fieldsOf(msg);
      const { required, defaults, optional } = HELPER_SCHEMAS[domain]!;
      const missing = required.find((k) => !(k in fields));
      if (missing) haError('invalid_format', `required key not provided @ data['${missing}']. Got None`);
      const known = new Set([...required, ...Object.keys(defaults), ...optional, 'icon']);
      const extra = Object.keys(fields).find((k) => !known.has(k));
      if (extra) haError('invalid_format', `extra keys not allowed @ data['${extra}']`);
      const replaced = { id: item.id, ...defaults, ...fields };
      items().splice(items().indexOf(item), 1, replaced);
      return replaced;
    });
    handlers[`${domain}/delete`] = adminOnly((_, msg) => {
      items().splice(items().indexOf(find(msg)), 1);
      return null;
    });
  }
  const ZONE_KEYS = ['name', 'latitude', 'longitude', 'radius', 'passive', 'icon'];
  const zoneFields = (msg: Message) => {
    const fields = Object.fromEntries(Object.entries(msg).filter(([k]) => !['id', 'type', 'zone_id'].includes(k)));
    const extra = Object.keys(fields).find((k) => !ZONE_KEYS.includes(k));
    return extra ? haError('invalid_format', `extra keys not allowed @ data['${extra}']`) : fields;
  };
  const zoneOf = (msg: Message) => zones.find((z) => z.id === msg.zone_id) ?? haError('not_found', `Unable to find zone_id ${String(msg.zone_id)}`);
  handlers['zone/list'] = () => zones;
  handlers['zone/create'] = adminOnly((_, msg) => {
    const fields = zoneFields(msg);
    const missing = ['name', 'latitude', 'longitude'].find((k) => !(k in fields));
    if (missing) haError('invalid_format', `required key not provided @ data['${missing}']. Got None`);
    const zone = { id: String(fields.name).toLowerCase().replace(/[^a-z0-9]+/g, '_'), radius: 100, passive: false, ...fields };
    zones.push(zone);
    return zone;
  });
  handlers['zone/update'] = adminOnly((_, msg) => Object.assign(zoneOf(msg), zoneFields(msg)));
  handlers['zone/delete'] = adminOnly((_, msg) => {
    zones.splice(zones.indexOf(zoneOf(msg)), 1);
    return null;
  });

  const entityOf = (kind: string, id: string) =>
    kind === 'script'
      ? (`script.${id}` in configs ? `script.${id}` : undefined)
      : Object.keys(configs).find((e) => e.startsWith(`${kind}.`) && configs[e]!.id === id);
  type Json = (status: number, value: unknown) => void;
  type Route = (match: RegExpExecArray, method: string | undefined, body: Record<string, unknown> | undefined, json: Json) => void;
  function configRoute([, kind, key]: RegExpExecArray, method: string | undefined, body: Record<string, unknown> | undefined, json: Json) {
    const id = decodeURIComponent(key!);
    const entity = entityOf(kind!, id);
    if (method === 'GET') return entity ? json(200, configs[entity]) : json(404, { message: 'Resource not found' });
    if (method === 'DELETE') {
      if (!entity) return json(400, { message: 'Resource not found' });
      delete configs[entity];
      return json(200, { result: 'ok' });
    }
    const missing = REQUIRED_KEYS[kind!]!.find((k) => !(k in (body ?? {})));
    if (missing) return json(400, { message: `Message malformed: required key not provided @ data['${missing}']` });
    configs[entity ?? `${kind}.${id}`] = kind === 'script' ? body! : { id, ...body };
    json(200, { result: 'ok' });
  }
  function stepOf(flow: FakeFlow, step: { menu: string[] } | { fields: Record<string, boolean> } = FLOW_STEPS[flow.handler]![flow.step_id]!) {
    const common = { flow_id: flow.flow_id, handler: flow.handler, step_id: flow.step_id, description_placeholders: null };
    if ('menu' in step) return { type: 'menu', ...common, menu_options: step.menu };
    const data_schema = Object.entries(step.fields).map(([name, required]) => ({ name, required, selector: { text: {} } }));
    return { type: 'form', ...common, data_schema, errors: null, last_step: null, preview: null };
  }
  function flowRoute([, id]: RegExpExecArray, method: string | undefined, body: Record<string, unknown> | undefined, json: Json) {
    const flow = flows.find((f) => f.flow_id === id);
    if (!flow) return json(404, { message: 'Invalid flow specified' });
    if (method === 'GET') return json(200, stepOf(flow));
    if (method === 'DELETE') {
      flows.splice(flows.indexOf(flow), 1);
      return json(200, { message: 'Flow aborted' });
    }
    const step = FLOW_STEPS[flow.handler]![flow.step_id]!;
    if ('menu' in step) {
      flow.step_id = String(body?.next_step_id);
      return json(200, stepOf(flow));
    }
    const input = body ?? {};
    const missing = Object.keys(step.fields).filter((k) => step.fields[k] && !(k in input));
    if (missing.length > 0) return json(400, { errors: Object.fromEntries(missing.map((k) => [k, 'required key not provided'])) });
    flows.splice(flows.indexOf(flow), 1);
    const entry = { entry_id: newFlowId(), domain: flow.handler, title: String(input[step.title]), source: flow.source, options: input };
    entries.push(entry);
    json(200, { type: 'create_entry', flow_id: flow.flow_id, handler: flow.handler, title: entry.title, description: null, description_placeholders: null, options: input, version: 1, minor_version: 1, result: served(entry) });
  }
  function optionsRoute([, id]: RegExpExecArray, method: string | undefined, body: Record<string, unknown> | undefined, json: Json) {
    const flow = optionsFlows.find((f) => f.flow_id === id);
    if (!flow) return json(404, { message: 'Invalid flow specified' });
    const entry = entries.find((e) => e.entry_id === flow.handler)!;
    const form = OPTIONS_FORMS[entry.domain]!;
    if (method === 'GET') return json(200, stepOf(flow, form));
    const input = body ?? {};
    const missing = Object.keys(form.fields).filter((k) => form.fields[k] && !(k in input));
    if (method === 'POST' && missing.length > 0) return json(400, { errors: Object.fromEntries(missing.map((k) => [k, 'required key not provided'])) });
    optionsFlows.splice(optionsFlows.indexOf(flow), 1);
    if (method === 'DELETE') return json(200, { message: 'Flow aborted' });
    entry.options = { ...entry.options, ...input };
    json(200, { type: 'create_entry', flow_id: flow.flow_id, handler: flow.handler, title: '', description: null, description_placeholders: null, version: 1, minor_version: 1 });
  }
  const served = ({ entry_id, domain, title, source }: FakeConfigEntry) => ({ entry_id, domain, title, source, state: 'loaded' });
  const newFlowId = () => randomBytes(16).toString('hex');
  const routes: [RegExp, Route][] = [
    [/^\/api\/config\/(automation|script|scene)\/config\/([^/]+)$/, configRoute],
    [/^\/api\/config\/config_entries\/flow_handlers(\?type=helper)?$/, ([, helper], _m, _b, json) => json(200, helper ? HELPER_HANDLERS : [...HELPER_HANDLERS, 'hue'])],
    [
      /^\/api\/config\/config_entries\/entry(\?type=helper)?$/,
      ([, helper], _m, _b, json) => json(200, entries.filter((e) => !helper || HELPER_HANDLERS.includes(e.domain)).map(served)),
    ],
    [
      /^\/api\/config\/config_entries\/flow$/,
      (_, _m, body, json) => {
        const handler = String(body?.handler);
        if (!(handler in FLOW_STEPS)) return json(404, { message: 'Invalid handler specified' });
        const flow = { flow_id: newFlowId(), handler, source: 'user', step_id: 'user' };
        flows.push(flow);
        json(200, stepOf(flow));
      },
    ],
    [/^\/api\/config\/config_entries\/flow\/([^/]+)$/, flowRoute],
    [
      /^\/api\/config\/config_entries\/options\/flow$/,
      (_, _m, body, json) => {
        const entry = entries.find((e) => e.entry_id === body?.handler);
        if (!entry || !(entry.domain in OPTIONS_FORMS)) return json(404, { message: 'Invalid handler specified' });
        const flow = { flow_id: newFlowId(), handler: entry.entry_id, source: 'user', step_id: OPTIONS_FORMS[entry.domain]!.step_id };
        optionsFlows.push(flow);
        json(200, stepOf(flow, OPTIONS_FORMS[entry.domain]));
      },
    ],
    [/^\/api\/config\/config_entries\/options\/flow\/([^/]+)$/, optionsRoute],
    [
      /^\/api\/config\/config_entries\/entry\/([^/?]+)$/,
      ([, id], method, _b, json) => {
        const entry = entries.find((e) => e.entry_id === id);
        if (method !== 'DELETE' || !entry) return json(method === 'DELETE' ? 404 : 405, { message: 'Invalid entry specified' });
        entries.splice(entries.indexOf(entry), 1);
        json(200, { require_restart: false });
      },
    ],
  ];
  function rest(req: IncomingMessage, res: ServerResponse, raw: string) {
    const json: Json = (status, value) => void res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(value));
    const token = /^Bearer (.+)$/.exec(req.headers.authorization ?? '')?.[1] ?? '';
    const body = raw === '' ? undefined : (JSON.parse(raw) as Record<string, unknown>);
    const type = `${req.method} ${req.url}`;
    received.push({ token, message: { type, ...(body !== undefined && { body }) } });
    for (const [pattern, route] of routes) {
      const match = pattern.exec(req.url ?? '');
      if (!match) continue;
      if (!options.users[token]?.is_admin) return void res.writeHead(401, { 'content-type': 'text/plain' }).end('401: Unauthorized');
      if (drop.has(type)) return void req.socket.destroy();
      if (hung) return;
      return route(match, req.method, body, json);
    }
    json(404, { message: 'Not found' });
  }

  const http = createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk: Buffer) => (raw += chunk.toString()));
    req.on('end', () => rest(req, res, raw));
  });
  const wss = new WebSocketServer({ server: http, path: '/api/websocket' });
  wss.on('connection', (ws) => {
    if (down) {
      refused++;
      return ws.terminate();
    }
    let token: string | undefined;
    let lastId = 0;
    const subscriptions = new Set<number>();
    const send = (m: unknown) => ws.send(JSON.stringify(m));
    send({ type: 'auth_required', ha_version: version });
    ws.on('message', (raw) => {
      const msg = JSON.parse((raw as Buffer).toString()) as Received['message'] & { access_token?: string };
      if (token === undefined) {
        if (msg.type === 'auth' && msg.access_token !== undefined && msg.access_token in options.users) {
          token = msg.access_token;
          send({ type: 'auth_ok', ha_version: version });
        } else {
          send({ type: 'auth_invalid', message: 'Invalid access token or password' });
          ws.close();
        }
        return;
      }
      received.push({ token, message: msg });
      const id = msg.id ?? 0;
      if (id <= lastId) {
        return send({ id, type: 'result', success: false, error: { code: 'id_reuse', message: 'Identifier values have to increase.' } });
      }
      lastId = id;
      if (hung) return;
      if (drop.has(msg.type)) return ws.terminate();
      if (stall.has(msg.type)) return;
      if (msg.type === 'ping') return send({ id, type: 'pong' });
      const handler = handlers[msg.type];
      if (!handler) {
        return send({ id, type: 'result', success: false, error: { code: 'unknown_command', message: 'Unknown command.' } });
      }
      try {
        const events: unknown[] = [];
        const result = handler(token, msg, { emit: (event) => void events.push(event), subscriptions });
        send({ id, type: 'result', success: true, result });
        if (events.length > 0) subscriptions.add(id);
        for (const event of events) send({ id, type: 'event', event });
      } catch (e) {
        if (!(e instanceof HaError)) throw e;
        send({ id, type: 'result', success: false, error: { code: e.code, message: e.message } });
      }
    });
  });
  await new Promise<void>((resolve) => http.listen(0, '127.0.0.1', resolve));
  const { port } = http.address() as AddressInfo;

  return {
    url: `http://127.0.0.1:${port}`,
    received,
    configs,
    helpers,
    zones,
    blueprints,
    dashboards,
    layouts,
    entries,
    flows,
    optionsFlows,
    drop,
    stall,
    async outage() {
      down = true;
      for (const ws of wss.clients) ws.terminate();
      const before = refused;
      for (let i = 0; i < 300 && refused === before; i++) await new Promise((r) => setTimeout(r, 10));
    },
    restore() {
      down = false;
      hung = false;
    },
    hang() {
      hung = true;
    },
    restart(change: { version?: string; revoke?: string } = {}) {
      version = change.version ?? version;
      if (change.revoke !== undefined) delete options.users[change.revoke];
      for (const ws of wss.clients) ws.terminate();
    },
    async close() {
      for (const ws of wss.clients) ws.terminate();
      await new Promise((resolve) => wss.close(resolve));
      await new Promise((resolve) => http.close(resolve));
    },
  };
}

