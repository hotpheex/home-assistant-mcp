import { setTimeout as sleep } from 'node:timers/promises';
import {
  createConnection,
  createLongLivedTokenAuth,
  ERR_CANNOT_CONNECT,
  ERR_CONNECTION_LOST,
  ERR_INVALID_AUTH,
  type Connection,
} from 'home-assistant-js-websocket';
import { isIssued, type Allowed, type Operation, type Tier } from './evaluator.ts';
import { FLOW_ID, FLOW_PATH, HELPER_DOMAINS, HELPER_LISTS, isSafeConfigId, OPTIONS_PATH, type Command, type RestRequest } from './ha.ts';
import type { Log } from './log.ts';

const MINIMUM_HA = [2026, 10] as const;
// home-assistant-js-websocket has no request timeout; unanswered pings drop half-open sockets.
const HEARTBEAT_MS = 30_000;
const TESTED_HA = [2026, 10] as const;

const READ_COMMANDS: Partial<Record<Operation, ReadonlySet<string>>> = {
  plain_read: new Set([
    'get_states',
    'get_services',
    'extract_from_target',
    'config/entity_registry/list',
    'config/entity_registry/get_entries',
    'config/device_registry/list',
    'config/area_registry/list',
    'config/label_registry/list',
    'config/floor_registry/list',
    'history/history_during_period',
    'logbook/get_events',
    'recorder/list_statistic_ids',
    'recorder/statistics_during_period',
    'lovelace/dashboards/list',
    'lovelace/config',
  ]),
  config_read: new Set([
    'automation/config',
    'script/config',
    'trace/list',
    'trace/get',
    'config/entity_registry/list',
    ...HELPER_DOMAINS.map((d) => `${d}/list`),
    'system_log/list',
    'zone/list',
    'lovelace/dashboards/list',
    'lovelace/config',
    'blueprint/list',
    'config_entries/flow/progress',
    'config_entries/get_single',
  ]),
  service_call: new Set(['get_services', 'get_states', 'extract_from_target']),
};

const ONE_SHOT: Partial<Record<Operation, ReadonlySet<string>>> = {
  plain_read: new Set(['render_template']),
};

const CONFIG_PATH = /^\/api\/config\/(automation|script|scene)\/config\/([^/]+)$/;

function isConfigLookupPath(path: string): boolean {
  const match = CONFIG_PATH.exec(path);
  if (!match) return false;
  try {
    return isSafeConfigId(decodeURIComponent(match[2]!));
  } catch {
    return false;
  }
}

const lookupable = (path: string) =>
  isConfigLookupPath(path) ||
  (Object.values(HELPER_LISTS) as string[]).includes(path) ||
  [FLOW_PATH, OPTIONS_PATH].some((flows) => path.startsWith(`${flows}/`) && FLOW_ID.test(path.slice(flows.length + 1)));

export class HaUnavailable extends Error {
  readonly sent: boolean;
  constructor(sent = false) {
    super();
    this.sent = sent;
  }
}

export class OutcomeUnknown extends Error {}

class Abandoned extends Error {}

// home-assistant-js-websocket rejects with bare code 3 before send, and `{ error: { code: 3 } }` if lost in flight.
function failureOf(e: unknown, write: boolean): unknown {
  if (e === ERR_CONNECTION_LOST) return new HaUnavailable();
  const lost =
    e instanceof Abandoned || (typeof e === 'object' && e !== null && 'error' in e && (e.error as { code?: unknown } | null)?.code === ERR_CONNECTION_LOST);
  if (lost) return write ? new OutcomeUnknown() : new HaUnavailable(true);
  return e;
}

export interface Gate {
  send(allowed: Allowed, command: Command): Promise<unknown>;
  ready(): boolean;
  connected: Promise<void>;
  rest(allowed: Allowed, request: RestRequest): Promise<{ status: number; body: unknown }>;
  close(): void;
  subscribeOnce(allowed: Allowed, command: Command): Promise<unknown>;
}

const releaseOf = (version: string) => version.split('.').slice(0, 2).map(Number);
const compare = (a: number[], b: readonly number[]) => a[0]! - b[0]! || a[1]! - b[1]!;

// HA returns text/plain on 401 responses from its REST API.
function jsonOf(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function issuedOnly(allowed: Allowed) {
  if (!isIssued(allowed)) throw new Error('the gate sends only an Allowed the evaluator issued');
}

export function openGate(url: string, tokens: ReadonlyMap<Tier, string>, log: Log, fatal: (reason: string) => void): Gate {
  const connections = new Map<Tier, Connection>();
  const opened = new Set<Connection>();
  let closed = false;
  const ready = () => [...tokens.keys()].every((tier) => connections.get(tier)?.connected);
  const { promise: connected, resolve: resolveConnected } = Promise.withResolvers<void>();

  function connectionFor(tier: Tier): Connection {
    const conn = connections.get(tier);
    if (!conn?.connected) throw new HaUnavailable();
    return conn;
  }

  async function check(tier: Tier, conn: Connection) {
    const release = releaseOf(conn.haVersion);
    if (!(compare(release, MINIMUM_HA) >= 0)) {
      return fatal(`Home Assistant ${conn.haVersion} is below the supported minimum ${MINIMUM_HA.join('.')}`);
    }
    if (compare(release, TESTED_HA) > 0) {
      log('warn', 'Home Assistant is newer than the release this server was tested with', { ha_version: conn.haVersion, tested: TESTED_HA.join('.') });
    }
    if (tier === 'users') {
      const user = await conn.sendMessagePromise<{ is_admin: boolean }>({ type: 'auth/current_user' });
      if (user.is_admin) return fatal('the users-tier HA token belongs to an HA admin; use a non-admin user');
    }
    connections.set(tier, conn);
    log('info', 'connected to Home Assistant', { tier, ha_version: conn.haVersion });
    if (ready()) resolveConnected();
  }

  const checked = (tier: Tier, conn: Connection) =>
    check(tier, conn).catch((e: unknown) => {
      if (!(failureOf(e, false) instanceof HaUnavailable)) fatal(`the ${tier}-tier check failed: ${String(e)}`);
    });

  async function connect(tier: Tier, token: string) {
    let conn: Connection | undefined;
    // home-assistant-js-websocket's connect has no abort hook, so own the retry loop to honour close().
    for (let attempt = 1; !conn; attempt++) {
      try {
        conn = await createConnection({ auth: createLongLivedTokenAuth(url, token) });
      } catch (e) {
        if (e === ERR_INVALID_AUTH) return fatal(`Home Assistant rejected the ${tier}-tier token`);
        if (e !== ERR_CANNOT_CONNECT) return fatal(`cannot connect to Home Assistant: ${String(e)}`);
        await sleep(Math.min(attempt, 5) * 1000, undefined, { ref: false });
      }
      if (closed) return conn?.close();
    }
    opened.add(conn);
    conn.addEventListener('ready', () => {
      connections.delete(tier);
      void checked(tier, conn);
    });
    conn.addEventListener('reconnect-error', (_conn, error) => {
      if (error === ERR_INVALID_AUTH) fatal(`Home Assistant rejected the ${tier}-tier token`);
    });
    await checked(tier, conn);
  }

  for (const [tier, token] of tokens) void connect(tier, token);

  const unanswered = new Set<Connection>();
  const requests = new Map<AbortController, boolean>();
  async function timed<T>(request: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const abort = new AbortController();
    requests.set(abort, false);
    try {
      return await request(abort.signal);
    } finally {
      requests.delete(abort);
    }
  }
  const abandoned = (signal: AbortSignal) => new Promise<never>((_, reject) => signal.addEventListener('abort', () => reject(new Abandoned())));
  const heartbeat = setInterval(() => {
    for (const [request, seen] of requests) {
      if (seen) request.abort();
      else requests.set(request, true);
    }
    for (const conn of opened) {
      if (!conn.connected) continue;
      if (unanswered.delete(conn)) conn.reconnect(true);
      else {
        unanswered.add(conn);
        conn.ping().then(
          () => unanswered.delete(conn),
          () => unanswered.delete(conn),
        );
      }
    }
  }, HEARTBEAT_MS);
  heartbeat.unref();

  return {
    async send(allowed, command) {
      issuedOnly(allowed);
      const write = allowed.write?.via === 'websocket' && command === allowed.write.command;
      if (!write && !READ_COMMANDS[allowed.operation]?.has(command.type)) {
        throw new Error(`${allowed.operation} may not send ${command.type}`);
      }
      const conn = connectionFor(allowed.tier);
      try {
        return await timed((signal) => Promise.race([conn.sendMessagePromise({ ...command }), abandoned(signal)]));
      } catch (e) {
        throw failureOf(e, write);
      }
    },
    ready,
    connected,
    async rest(allowed, request) {
      issuedOnly(allowed);
      const write = allowed.write?.via === 'rest' && request === allowed.write.request;
      const lookup = allowed.operation === 'config_read' && request.method === 'GET' && lookupable(request.path);
      if (!write && !lookup) throw new Error(`${allowed.operation} may not send ${request.method} ${request.path}`);
      connectionFor(allowed.tier);
      try {
        return await timed(async (signal) => {
          const res = await fetch(`${url}${request.path}`, {
            method: request.method,
            headers: { authorization: `Bearer ${tokens.get(allowed.tier)}`, 'content-type': 'application/json' },
            ...(request.body !== undefined && { body: JSON.stringify(request.body) }),
            signal,
          });
          return { status: res.status, body: jsonOf(await res.text()) };
        });
      } catch {
        // fetch does not distinguish connection-refused from a mid-flight drop.
        throw write ? new OutcomeUnknown() : new HaUnavailable(true);
      }
    },
    async subscribeOnce(allowed, command) {
      issuedOnly(allowed);
      if (!ONE_SHOT[allowed.operation]?.has(command.type)) throw new Error(`${allowed.operation} may not subscribe to ${command.type}`);
      const conn = connectionFor(allowed.tier);
      try {
        return await timed(async (signal) => {
          const gone = abandoned(signal);
          const first = Promise.withResolvers<unknown>();
          const subscribed = conn.subscribeMessage(first.resolve, { ...command }, { resubscribe: false });
          try {
            await Promise.race([subscribed, gone]);
            return await Promise.race([first.promise, gone]);
          } finally {
            const ended = subscribed.then(
              (unsubscribe) => unsubscribe(),
              () => {},
            );
            await Promise.race([ended, gone]).catch(() => {});
          }
        });
      } catch (e) {
        throw failureOf(e, false);
      }
    },
    close() {
      closed = true;
      clearInterval(heartbeat);
      for (const conn of opened) conn.close();
      connections.clear();
    },
  };
}
