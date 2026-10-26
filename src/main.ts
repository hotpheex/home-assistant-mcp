import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { parseArgs } from 'node:util';
import { hashKey } from './auth.ts';
import { neededTiers } from './evaluator.ts';
import { openGate } from './gate.ts';
import { createHttp } from './http.ts';
import { logger, optedIn, type Write } from './log.ts';
import { parsePolicy, policyWarnings } from './policy.ts';
import { readSettings, readTokens } from './settings.ts';

export interface Io {
  write: Write;
  exit: (code: number) => void;
}

export interface Running {
  address: string;
  close(): Promise<void>;
}

/** The CLI: `serve` (the default) and `keygen`. Errors log one line and exit non-zero. */
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
  if (command !== 'serve') return fail(`unknown command "${command}"; use serve or keygen`);

  let settings, policy, tokens;
  try {
    settings = readSettings(env, args.values.policy);
    policy = parsePolicy(readFileSync(settings.HAMCP_POLICY, 'utf8'));
    log('info', 'policy loaded', { policy_sha256: policy.sha256 });
    for (const warning of policyWarnings(policy, new Date())) log('warn', warning);
    tokens = readTokens(env, neededTiers(policy));
  } catch (e) {
    return fail((e as Error).message);
  }

  let stopping: Promise<void> | undefined;
  const close = () =>
    (stopping ??= (async () => {
      gate.close();
      await server.close();
      server.http.closeAllConnections();
      await new Promise((resolve) => server.http.close(resolve));
    })());
  const gate = openGate(settings.HAMCP_HA_URL, tokens, log, (reason) => {
    log('error', reason);
    void close().then(() => io.exit(1));
  });
  const server = createHttp(policy, settings.HAMCP_ALLOWED_ORIGINS, gate, log, optedIn(audit, settings.HAMCP_AUDIT_WRITES));
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
