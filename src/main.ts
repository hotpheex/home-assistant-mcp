import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { parseArgs } from 'node:util';
import { expiryWarnings, hashKey } from './auth.ts';
import { NAME_LOOKUP, neededTiers } from './evaluator.ts';
import { HaUnavailable, openGate } from './gate.ts';
import { createHttp } from './http.ts';
import { logger, type Log } from './log.ts';
import { parsePolicy, policyWarnings, type Policy } from './policy.ts';
import { unknownNames } from './resolver.ts';
import { readSettings, readTokens, SettingsError } from './settings.ts';

const CONNECT_WAIT_MS = 10_000;

export interface Io {
  write: (line: string) => void;
  exit: (code: number) => void;
}

export interface Running {
  address: string;
  close(): Promise<void>;
}

function loadPolicy(path: string, log: Log): Policy {
  const policy = parsePolicy(readFileSync(path, 'utf8'));
  log('info', 'policy loaded', { policy_sha256: policy.sha256 });
  return policy;
}

async function checkPolicy(path: string, env: Record<string, string | undefined>, log: Log): Promise<boolean> {
  const policy = loadPolicy(path, log);
  const now = new Date();
  for (const warning of [...policyWarnings(policy, now), ...expiryWarnings(policy, now)]) log('warn', warning);
  if (env.HAMCP_HA_URL === undefined) return true;

  const { HAMCP_HA_URL } = readSettings(env, path);
  if (!env.HAMCP_HA_USERS_TOKEN && !env.HAMCP_HA_USERS_TOKEN_FILE) {
    throw new SettingsError('check resolves names at the users tier; set HAMCP_HA_USERS_TOKEN or HAMCP_HA_USERS_TOKEN_FILE');
  }
  const aborted = Promise.withResolvers<never>();
  aborted.promise.catch(() => {});
  const gate = openGate(HAMCP_HA_URL, readTokens(env, ['users']), log, (reason) => aborted.reject(new Error(reason)));
  const timer = setTimeout(() => aborted.reject(new Error(`Home Assistant at ${HAMCP_HA_URL} is unavailable`)), CONNECT_WAIT_MS);
  timer.unref();
  try {
    await Promise.race([gate.connected, aborted.promise]);
    const unknown = await Promise.race([unknownNames(policy, (command) => gate.send(NAME_LOOKUP, command)), aborted.promise]);
    for (const problem of unknown) log('error', problem);
    return unknown.length === 0;
  } catch (e) {
    if (e instanceof HaUnavailable) throw new Error(`Home Assistant at ${HAMCP_HA_URL} is unavailable`);
    throw e;
  } finally {
    clearTimeout(timer);
    gate.close();
  }
}

export async function run(argv: string[], env: Record<string, string | undefined>, io: Io): Promise<Running | undefined> {
  const { log, audit } = logger(io.write);
  const fail = (message: string) => {
    log('error', message);
    io.exit(1);
    return undefined;
  };

  let args;
  try {
    args = parseArgs({ args: argv, options: { policy: { type: 'string' } }, allowPositionals: true });
  } catch (e) {
    return fail((e as Error).message);
  }
  const [command = 'serve'] = args.positionals;

  if (command === 'keygen') {
    const key = `hamcp_${randomBytes(32).toString('base64url')}`;
    io.write(`key: ${key}`);
    io.write(`sha256: ${hashKey(key).toString('hex')}`);
    return undefined;
  }
  if (command === 'check') {
    const path = args.positionals[1] ?? args.values.policy ?? env.HAMCP_POLICY;
    if (!path) return fail('usage: check <policy>');
    try {
      io.exit((await checkPolicy(path, env, log)) ? 0 : 1);
    } catch (e) {
      return fail((e as Error).message);
    }
    return undefined;
  }
  if (command !== 'serve') return fail(`unknown command "${command}"; use serve, check or keygen`);

  let settings, policy, tokens;
  try {
    settings = readSettings(env, args.values.policy);
    policy = loadPolicy(settings.HAMCP_POLICY, log);
    for (const warning of expiryWarnings(policy, new Date())) log('warn', warning);
    tokens = readTokens(env, neededTiers(policy));
    if (!tokens.has('admin') && (env.HAMCP_HA_ADMIN_TOKEN || env.HAMCP_HA_ADMIN_TOKEN_FILE)) {
      log('warn', 'HAMCP_HA_ADMIN_TOKEN is set but no Grant needs config read or config write, so it is never read or used; remove it');
    }
  } catch (e) {
    return fail((e as Error).message);
  }

  const expiryCheck = setInterval(() => {
    for (const warning of expiryWarnings(policy, new Date())) log('warn', warning);
  }, 86_400_000);
  expiryCheck.unref();
  let stopping: Promise<void> | undefined;
  const close = () =>
    (stopping ??= (async () => {
      clearInterval(expiryCheck);
      gate.close();
      await server.close();
      server.http.closeAllConnections();
      await new Promise((resolve) => server.http.close(resolve));
    })());
  const gate = openGate(settings.HAMCP_HA_URL, tokens, log, (reason) => {
    log('error', reason);
    void close().then(() => io.exit(1));
  });
  void gate.connected
    .then(async () => {
      for (const warning of policyWarnings(policy, new Date())) log('warn', warning);
      const unknown = tokens.has('users') ? await unknownNames(policy, (command) => gate.send(NAME_LOOKUP, command)) : [];
      for (const warning of unknown) log('warn', warning);
      log('info', 'startup warnings logged');
    })
    .catch((e: unknown) => log('warn', 'cannot resolve Policy names against Home Assistant', { error: String(e) }));
  const server = createHttp(policy, settings.HAMCP_ALLOWED_ORIGINS, gate, log, audit, {
    auditReads: settings.HAMCP_AUDIT_READS,
    auditWrites: settings.HAMCP_AUDIT_WRITES,
  });
  const { host, port } = settings.HAMCP_LISTEN;
  try {
    await new Promise<void>((resolve, reject) => server.http.once('error', reject).listen(port, host, resolve));
  } catch (e) {
    await close();
    return fail(`cannot listen on ${host}:${port}: ${(e as Error).message}`);
  }
  const bound = server.http.address() as AddressInfo;
  const address = `${bound.family === 'IPv6' ? `[${bound.address}]` : bound.address}:${bound.port}`;
  log('info', 'listening', { address });
  return { address, close };
}

if (import.meta.main) {
  await run(process.argv.slice(2), process.env, {
    write: (line) => process.stdout.write(`${line}\n`),
    exit: (code) => process.exit(code),
  });
}
