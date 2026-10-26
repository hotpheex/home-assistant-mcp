import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
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
  /** Served only by get_entries, as in HA. */
  aliases?: string[];
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
  entities?: FakeEntity[];
  devices?: FakeEntry[];
  areas?: FakeEntry[];
  labels?: FakeEntry[];
  floors?: FakeEntry[];
  history?: FakeChange[];
  logbook?: FakeLogEntry[];
  /** Automation, script and scene configs, keyed by entity_id; automation and scene entries carry their config `id`. */
  configs?: Record<string, Record<string, unknown>>;
  traces?: FakeTrace[];
  /** Stored (UI) helpers, keyed by helper domain. */
  helpers?: Record<string, Record<string, unknown>[]>;
}

const HELPER_DOMAINS = ['input_boolean', 'input_number', 'input_select', 'input_text', 'input_datetime', 'input_button', 'counter', 'timer', 'schedule'];
/** HA validates the whole body of a config POST, so a partial one is refused. */
const REQUIRED_KEYS: Record<string, string[]> = { automation: ['triggers', 'actions'], script: ['sequence'], scene: ['name', 'entities'] };

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

const isoNow = () => new Date().toISOString();
const seconds = (iso: string) => Date.parse(iso) / 1000;
type Message = Received['message'];
const inWindow = (when: string, msg: Message) =>
  Date.parse(when) >= Date.parse(msg.start_time as string) &&
  Date.parse(when) <= (msg.end_time === undefined ? Date.now() : Date.parse(msg.end_time as string));

/** Hand-written HA 2026.10: speaks the WebSocket protocol to the real client, answers config REST, and records every command and request. */
export async function startFakeHa(options: FakeHaOptions) {
  const version = options.version ?? '2026.10.4';
  const received: Received[] = [];
  const entities = options.entities ?? [];
  const entityEntry = (e: FakeEntity) => {
    const entry: Partial<FakeEntity> = { name: null, device_id: null, area_id: null, labels: [], ...e };
    delete entry.aliases;
    return entry;
  };
  type Handler = (token: string, msg: Message) => unknown;
  /** HA's require_admin. */
  const adminOnly = (handler: Handler): Handler => (token, msg) =>
    options.users[token]?.is_admin ? handler(token, msg) : haError('unauthorized', 'Unauthorized');
  const configs = structuredClone(options.configs ?? {});
  const helpers = structuredClone(options.helpers ?? {});
  const configOf = adminOnly((_, msg) => {
    const config = configs[msg.entity_id as string];
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
    handlers[`${domain}/update`] = adminOnly((_, msg) => Object.assign(find(msg), fieldsOf(msg)));
    handlers[`${domain}/delete`] = adminOnly((_, msg) => {
      items().splice(items().indexOf(find(msg)), 1);
      return null;
    });
  }

  /** HA's config REST API: automation and scene entries by config id, scripts by object key. */
  const entityOf = (kind: string, id: string) =>
    kind === 'script'
      ? (`script.${id}` in configs ? `script.${id}` : undefined)
      : Object.keys(configs).find((e) => e.startsWith(`${kind}.`) && configs[e]!.id === id);
  function rest(req: IncomingMessage, res: ServerResponse, raw: string) {
    const json = (status: number, value: unknown) => void res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(value));
    const match = /^\/api\/config\/(automation|script|scene)\/config\/([^/]+)$/.exec(req.url ?? '');
    if (!match) return json(404, { message: 'Not found' });
    const token = /^Bearer (.+)$/.exec(req.headers.authorization ?? '')?.[1] ?? '';
    if (!options.users[token]?.is_admin) return void res.writeHead(401, { 'content-type': 'text/plain' }).end('401: Unauthorized');
    const body = raw === '' ? undefined : (JSON.parse(raw) as Record<string, unknown>);
    received.push({ token, message: { type: `${req.method} ${req.url}`, ...(body !== undefined && { body }) } });
    const [, kind, key] = match as unknown as [string, string, string];
    const id = decodeURIComponent(key);
    const entity = entityOf(kind, id);
    if (req.method === 'GET') return entity ? json(200, configs[entity]) : json(404, { message: 'Resource not found' });
    if (req.method === 'DELETE') {
      if (!entity) return json(400, { message: 'Resource not found' });
      delete configs[entity];
      return json(200, { result: 'ok' });
    }
    const missing = REQUIRED_KEYS[kind]!.find((k) => !(k in (body ?? {})));
    if (missing) return json(400, { message: `Message malformed: required key not provided @ data['${missing}']` });
    configs[entity ?? `${kind}.${id}`] = kind === 'script' ? body! : { id, ...body };
    json(200, { result: 'ok' });
  }

  const http = createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk: Buffer) => (raw += chunk.toString()));
    req.on('end', () => rest(req, res, raw));
  });
  const wss = new WebSocketServer({ server: http, path: '/api/websocket' });
  wss.on('connection', (ws) => {
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
    configs,
    helpers,
    async close() {
      for (const ws of wss.clients) ws.terminate();
      await new Promise((resolve) => wss.close(resolve));
      await new Promise((resolve) => http.close(resolve));
    },
  };
}

export type FakeHa = Awaited<ReturnType<typeof startFakeHa>>;
