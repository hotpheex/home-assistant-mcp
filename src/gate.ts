import { setTimeout as sleep } from 'node:timers/promises';
import {
  createConnection,
  createLongLivedTokenAuth,
  ERR_CANNOT_CONNECT,
  ERR_CONNECTION_LOST,
  ERR_INVALID_AUTH,
  type Connection,
} from 'home-assistant-js-websocket';
import { HELPER_DOMAINS, isIssued, type Allowed, type Operation, type Tier } from './evaluator.ts';
import type { Log } from './log.ts';

const MINIMUM_HA = [2026, 10] as const;
/** The client has no timeout, so a half-open connection would hang every send; a ping unanswered for a whole beat drops it. */
const HEARTBEAT_MS = 30_000;
/** The release of the pinned-stable HA in ci.yml, kept in step by a startup test; a newer release warns but serves. */
const TESTED_HA = [2026, 10] as const;

/** Read Operations, and a service call's lookups, may send only these read-only commands. */
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
  ]),
  config_read: new Set(['automation/config', 'script/config', 'trace/list', 'trace/get', ...HELPER_DOMAINS.map((d) => `${d}/list`)]),
  service_call: new Set(['get_services', 'get_states', 'extract_from_target']),
};
/** Config read may GET a stored config; any other REST request must be the exact write an Allowed names. */
const CONFIG_PATH = /^\/api\/config\/(automation|script|scene)\/config\/[^/]+$/;

export type Command = { type: string } & Record<string, unknown>;
/** A request to HA's config REST API, the only REST the server makes. */
export interface RestRequest {
  method: 'GET' | 'POST' | 'DELETE';
  path: string;
  body?: unknown;
}

/** HA did not answer; `sent` when the request may have left the process, which only a read may report. */
export class HaUnavailable extends Error {
  readonly sent: boolean;
  constructor(sent = false) {
    super();
    this.sent = sent;
  }
}
/** The connection dropped after a write was sent, so it may or may not have run. */
export class OutcomeUnknown extends Error {}

/** The client rejects with a bare 3 when nothing was sent, and with a whole envelope coded 3 when the result never came. */
function failureOf(e: unknown, write: boolean): unknown {
  if (e === ERR_CONNECTION_LOST) return new HaUnavailable();
  const lost = typeof e === 'object' && e !== null && 'error' in e && (e.error as { code?: unknown } | null)?.code === ERR_CONNECTION_LOST;
  if (lost) return write ? new OutcomeUnknown() : new HaUnavailable(true);
  return e;
}

export interface Gate {
  send(allowed: Allowed, command: Command): Promise<unknown>;
  /** Every needed tier is connected and checked. */
  ready(): boolean;
  /** Resolves the first time the gate is ready. */
  connected: Promise<void>;
  /** Answers with HA's status and JSON body, leaving their meaning to the caller. */
  rest(allowed: Allowed, request: RestRequest): Promise<{ status: number; body: unknown }>;
  close(): void;
}

const releaseOf = (version: string) => version.split('.').slice(0, 2).map(Number);
const compare = (a: number[], b: readonly number[]) => (a[0]! - b[0]!) || (a[1]! - b[1]!);

/** A 401 from HA is text/plain. */
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

/**
 * The only code that reaches HA. It holds one connection per needed tier, plus REST for config, and exits the server
 * (through `fatal`) on a rejected token, an HA below the minimum, or an admin behind the users tier.
 */
export function openGate(url: string, tokens: ReadonlyMap<Tier, string>, log: Log, fatal: (reason: string) => void): Gate {
  const connections = new Map<Tier, Connection>();
  const opened = new Set<Connection>();
  let closed = false;
  const ready = () => [...tokens.keys()].every((tier) => connections.get(tier)?.connected);
  const { promise: connected, resolve: resolveConnected } = Promise.withResolvers<void>();

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

  /** A connection lost during the checks only delays them: the client reconnects, and `ready` runs them again. */
  const checked = (tier: Tier, conn: Connection) =>
    check(tier, conn).catch((e: unknown) => {
      if (!(failureOf(e, false) instanceof HaUnavailable)) fatal(`the ${tier}-tier check failed: ${String(e)}`);
    });

  async function connect(tier: Tier, token: string) {
    let conn: Connection | undefined;
    // Our own backoff loop rather than the client's, so close() also stops a server still waiting for HA.
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
  /** REST in flight, marked once a beat has seen it, so one unanswered at the next beat is aborted: a 30–60 s timeout. */
  const requests = new Map<AbortController, boolean>();
  const heartbeat = setInterval(() => {
    for (const [request, seen] of requests) {
      if (seen) request.abort();
      else requests.set(request, true);
    }
    for (const conn of opened) {
      if (!conn.connected) continue;
      // Dropping rejects the sends waiting on it, readiness falls, and the client reconnects.
      if (unanswered.delete(conn)) conn.reconnect(true);
      else {
        unanswered.add(conn);
        conn.ping().then(() => unanswered.delete(conn), () => unanswered.delete(conn));
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
      const conn = connections.get(allowed.tier);
      if (!conn?.connected) throw new HaUnavailable();
      try {
        return await conn.sendMessagePromise({ ...command });
      } catch (e) {
        throw failureOf(e, write);
      }
    },
    ready,
    connected,
    async rest(allowed, request) {
      issuedOnly(allowed);
      const write = allowed.write?.via === 'rest' && request === allowed.write.request;
      const lookup = allowed.operation === 'config_read' && request.method === 'GET' && CONFIG_PATH.test(request.path);
      if (!write && !lookup) throw new Error(`${allowed.operation} may not send ${request.method} ${request.path}`);
      if (!connections.get(allowed.tier)?.connected) throw new HaUnavailable();
      const abort = new AbortController();
      requests.set(abort, false);
      let res: Response, text: string;
      try {
        res = await fetch(`${url}${request.path}`, {
          method: request.method,
          headers: { authorization: `Bearer ${tokens.get(allowed.tier)}`, 'content-type': 'application/json' },
          ...(request.body !== undefined && { body: JSON.stringify(request.body) }),
          signal: abort.signal,
        });
        text = await res.text();
      } catch {
        // fetch cannot tell a refused connection from one dropped or abandoned mid-request, so a write errs towards unknown.
        throw write ? new OutcomeUnknown() : new HaUnavailable(true);
      } finally {
        requests.delete(abort);
      }
      return { status: res.status, body: jsonOf(text) };
    },
    close() {
      closed = true;
      clearInterval(heartbeat);
      for (const conn of opened) conn.close();
      connections.clear();
    },
  };
}
