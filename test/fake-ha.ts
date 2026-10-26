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

const isoNow = () => new Date().toISOString();
const seconds = (iso: string) => Date.parse(iso) / 1000;
type Message = Received['message'];
const inWindow = (when: string, msg: Message) =>
  Date.parse(when) >= Date.parse(msg.start_time as string) &&
  Date.parse(when) <= (msg.end_time === undefined ? Date.now() : Date.parse(msg.end_time as string));

/** Hand-written HA 2026.10: speaks the WebSocket protocol to the real client and records every command. */
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
    async close() {
      for (const ws of wss.clients) ws.terminate();
      await new Promise((resolve) => wss.close(resolve));
      await new Promise((resolve) => http.close(resolve));
    },
  };
}

export type FakeHa = Awaited<ReturnType<typeof startFakeHa>>;
