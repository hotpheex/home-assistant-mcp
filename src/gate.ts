import { setTimeout as sleep } from 'node:timers/promises';
import {
  createConnection,
  createLongLivedTokenAuth,
  ERR_CANNOT_CONNECT,
  ERR_CONNECTION_LOST,
  ERR_INVALID_AUTH,
  type Connection,
} from 'home-assistant-js-websocket';
import type { Allowed, Operation, Tier } from './evaluator.ts';
import type { Log } from './log.ts';

const MINIMUM_HA = [2026, 10] as const;
/** The pinned-stable HA the suite runs against; a newer release warns but serves. */
const TESTED_HA = [2026, 10] as const;

/** Read Operations, and a service call's lookups, may send only these read-only commands. */
const READ_COMMANDS: Partial<Record<Operation, ReadonlySet<string>>> = {
  plain_read: new Set(['get_states', 'get_services', 'extract_from_target']),
  config_read: new Set(),
  service_call: new Set(['get_services', 'get_states', 'extract_from_target']),
};

export type Command = { type: string } & Record<string, unknown>;

/** Nothing left the process. */
export class HaUnavailable extends Error {}
/** The connection dropped after a write was sent, so it may or may not have run. */
export class OutcomeUnknown extends Error {}
/** HA answered with an error result; the message is HA's. */
export class HaError extends Error {}

/** The client rejects with a bare 3 when nothing was sent, and with a whole envelope coded 3 when the result never came. */
function failureOf(e: unknown, write: boolean): unknown {
  if (e === ERR_CONNECTION_LOST) return new HaUnavailable();
  if (typeof e !== 'object' || e === null) return e;
  if ('error' in e && (e.error as { code?: unknown } | null)?.code === ERR_CONNECTION_LOST) return write ? new OutcomeUnknown() : new HaUnavailable();
  if ('code' in e && typeof e.code === 'string' && 'message' in e) return new HaError(String(e.message));
  return e;
}

export interface Gate {
  send(allowed: Allowed, command: Command): Promise<unknown>;
  close(): void;
}

const releaseOf = (version: string) => version.split('.').slice(0, 2).map(Number);
const compare = (a: number[], b: readonly number[]) => (a[0]! - b[0]!) || (a[1]! - b[1]!);

/**
 * The only code that reaches HA. It holds one connection per needed tier and exits the server
 * (through `fatal`) on a rejected token, an HA below the minimum, or an admin behind the users tier.
 */
export function openGate(url: string, tokens: ReadonlyMap<Tier, string>, log: Log, fatal: (reason: string) => void): Gate {
  const connections = new Map<Tier, Connection>();
  const opened = new Set<Connection>();
  let closed = false;

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
  }

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
      void check(tier, conn).catch((e: unknown) => fatal(`the ${tier}-tier check failed: ${String(e)}`));
    });
    conn.addEventListener('reconnect-error', (_conn, error) => {
      if (error === ERR_INVALID_AUTH) fatal(`Home Assistant rejected the ${tier}-tier token`);
    });
    await check(tier, conn).catch((e: unknown) => fatal(`the ${tier}-tier check failed: ${String(e)}`));
  }

  for (const [tier, token] of tokens) void connect(tier, token);

  return {
    async send(allowed, command) {
      if (command !== allowed.command && !READ_COMMANDS[allowed.operation]?.has(command.type)) {
        throw new Error(`${allowed.operation} may not send ${command.type}`);
      }
      const conn = connections.get(allowed.tier);
      if (!conn?.connected) throw new HaUnavailable();
      try {
        return await conn.sendMessagePromise({ ...command });
      } catch (e) {
        throw failureOf(e, command === allowed.command);
      }
    },
    close() {
      closed = true;
      for (const conn of opened) conn.close();
      connections.clear();
    },
  };
}
