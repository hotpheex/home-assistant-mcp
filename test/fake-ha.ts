import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { WebSocketServer } from 'ws';

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
  /** Served only by get_entries, as in HA. */
  aliases?: string[];
}
export interface ServiceDescription {
  name?: string;
  fields?: Record<string, unknown>;
  target?: Record<string, unknown>;
  response?: { optional: boolean };
}
/** A device, area, label or floor registry entry, served as given. */
export type FakeEntry = Record<string, unknown>;
/** A recorded state change, served by history. */
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
  /** Accepted tokens, each mapped to its HA user. */
  users: Record<string, { is_admin: boolean }>;
  states?: FakeState[];
  services?: Record<string, Record<string, ServiceDescription>>;
  /** What a responding service returns, by `domain.service`. */
  responses?: Record<string, unknown>;
  entities?: FakeEntity[];
  devices?: FakeEntry[];
  areas?: FakeEntry[];
  labels?: FakeEntry[];
  floors?: FakeEntry[];
  history?: FakeChange[];
  logbook?: FakeLogEntry[];
  /** Automation and script configs, keyed by entity_id. */
  configs?: Record<string, Record<string, unknown>>;
  traces?: FakeTrace[];
}

/** A stored run: summary fields plus the sections only trace/get returns. */
export interface FakeTrace extends Record<string, unknown> {
  domain: 'automation' | 'script';
  item_id: string;
  run_id: string;
  timestamp: { start: string; finish: string };
}
const TRACE_SECTIONS = ['trace', 'config', 'blueprint_inputs', 'context'];

/** A command the server sent after authenticating, with the token of the connection it came on. */
export interface Received {
  token: string;
  message: { type: string; id?: number } & Record<string, unknown>;
}

/** Thrown by a handler to answer with an HA error result. */
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
type Entity = Required<Omit<FakeEntity, 'name' | 'aliases'>>;
type Device = { id: string; area_id: string | null; labels: string[]; parent_device_id: string | null };
/** The registry fields `extract_from_target` reads, with HA's defaults filled in. */
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

/** A port of HA 2026.10's `helpers/target.py` expansion, rule for rule. */
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

/** Hand-written HA 2026.10: speaks the WebSocket protocol to the real client and records every command. */
export async function startFakeHa(options: FakeHaOptions) {
  let version = options.version ?? '2026.10.4';
  const received: Received[] = [];
  let contexts = 0;
  const drop = new Set<string>();
  let down = false;
  let hung = false;
  let refused = 0;
  const entities = options.entities ?? [];
  const entityEntry = (e: FakeEntity) => {
    const entry: Partial<FakeEntity> = { name: null, device_id: null, area_id: null, labels: [], hidden_by: null, disabled_by: null, entity_category: null, ...e };
    delete entry.aliases;
    return entry;
  };
  type Handler = (token: string, msg: Message) => unknown;
  /** HA's require_admin. */
  const adminOnly = (handler: Handler): Handler => (token, msg) =>
    options.users[token]?.is_admin ? handler(token, msg) : haError('unauthorized', 'Unauthorized');
  const configOf = adminOnly((_, msg) => {
    const config = options.configs?.[msg.entity_id as string];
    return config && (msg.entity_id as string).startsWith(`${msg.type.split('/')[0]}.`) ? { config } : haError('not_found', 'Entity not found');
  });
  const handlers: Record<string, Handler> = {
    supported_features: () => null,
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
    'config/device_registry/list': () => options.devices ?? [],
    'config/area_registry/list': () => options.areas ?? [],
    'config/label_registry/list': () => options.labels ?? [],
    'config/floor_registry/list': () => options.floors ?? [],
    'history/history_during_period': (_, msg) => {
      const out: Record<string, { s: string; lu: number }[]> = {};
      for (const c of options.history ?? []) {
        if ((msg.entity_ids as string[]).includes(c.entity_id) && inWindow(c.when, msg)) (out[c.entity_id] ??= []).push({ s: c.state, lu: seconds(c.when) });
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
    'logbook/get_events': (_, msg) =>
      (options.logbook ?? [])
        .filter((e) => inWindow(e.when, msg) && (msg.entity_ids === undefined || (msg.entity_ids as string[]).includes(e.entity_id ?? '')))
        .map((e) => ({ ...e, when: seconds(e.when) })),
  };

  const http = createServer((_req, res) => res.writeHead(404).end());
  const wss = new WebSocketServer({ server: http, path: '/api/websocket' });
  wss.on('connection', (ws) => {
    if (down) {
      refused++;
      return ws.terminate();
    }
    let token: string | undefined;
    let lastId = 0;
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
      if (msg.type === 'ping') return send({ id, type: 'pong' });
      const handler = handlers[msg.type];
      if (!handler) {
        return send({ id, type: 'result', success: false, error: { code: 'unknown_command', message: 'Unknown command.' } });
      }
      try {
        send({ id, type: 'result', success: true, result: handler(token, msg) });
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
    /** Command types answered by dropping the connection after recording them, as when HA goes away mid-call. */
    drop,
    /** Drops every connection and refuses new ones, until the client has seen the outage by trying to reconnect. */
    async outage() {
      down = true;
      for (const ws of wss.clients) ws.terminate();
      const before = refused;
      for (let i = 0; i < 300 && refused === before; i++) await new Promise((r) => setTimeout(r, 10));
    },
    /** Accepts connections again after an outage, and answers again after a hang. */
    restore() {
      down = false;
      hung = false;
    },
    /** Keeps every connection open but answers nothing, as a half-open TCP connection does. */
    hang() {
      hung = true;
    },
    /** Drops every connection, as an HA restart does, optionally coming back at another version or without a token. */
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

export type FakeHa = Awaited<ReturnType<typeof startFakeHa>>;
