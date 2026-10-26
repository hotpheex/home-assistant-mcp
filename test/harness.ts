import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { TestContext } from 'node:test';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { run } from '../src/main.ts';
import { startFakeHa, type FakeHaOptions, type FakeState } from './fake-ha.ts';

export const USERS_TOKEN = 'users-token';
export const ADMIN_TOKEN = 'admin-token';
export const ERAS = ['legacy', 'modern'] as const;

const state = (entity_id: string, friendly_name: string, value: string): FakeState => ({
  entity_id,
  state: value,
  attributes: { friendly_name },
});
export const HOUSE: FakeState[] = [
  state('switch.coffee_maker', 'Coffee Maker', 'off'),
  state('light.kitchen', 'Kitchen Ceiling', 'on'),
  state('sensor.kitchen_temperature', 'Kitchen Temperature', '21.5'),
  state('light.living_room', 'Living Room Lamp', 'off'),
  state('lock.front_door', 'Front Door', 'locked'),
];

export function newKey() {
  const key = `hamcp_${randomBytes(32).toString('base64url')}`;
  return { key, sha256: createHash('sha256').update(key).digest('hex') };
}

export async function fakeHa(t: TestContext, options: Partial<FakeHaOptions> = {}) {
  const ha = await startFakeHa({
    users: { [USERS_TOKEN]: { is_admin: false }, [ADMIN_TOKEN]: { is_admin: true } },
    states: HOUSE,
    services: { light: { turn_on: { target: { entity: [{ domain: ['light'] }] } } } },
    ...options,
  });
  t.after(() => ha.close());
  return ha;
}

/** Runs the CLI in-process as a deployer would: argv and env in; stdout lines and the exit code out. */
export async function runCli(t: TestContext, args: string[], env: Record<string, string | undefined>) {
  const lines: string[] = [];
  let exit: (code: number) => void = () => {};
  const exited = new Promise<number>((resolve) => (exit = resolve));
  const handle = await run(args, env, { write: (line) => lines.push(line), exit: (code) => exit(code) });
  t.after(() => handle?.close());
  const records = () => lines.map((l) => JSON.parse(l) as Record<string, unknown>);
  return { lines, records, audits: () => records().filter((r) => r.audit === true), exited, handle };
}

export function writePolicy(yaml: string) {
  const path = join(mkdtempSync(join(tmpdir(), 'hamcp-')), 'policy.yaml');
  writeFileSync(path, yaml);
  return path;
}

export async function until(check: () => boolean, what: string) {
  for (let i = 0; i < 200 && !check(); i++) await new Promise((r) => setTimeout(r, 10));
  if (!check()) throw new Error(`timed out waiting for ${what}`);
}

/** Starts the server against `ha` and waits until every needed tier is connected. */
export async function startServer(
  t: TestContext,
  policy: string,
  ha: { url: string },
  env: Record<string, string | undefined> = {},
) {
  const cli = await runCli(t, ['serve'], {
    HAMCP_POLICY: writePolicy(policy),
    HAMCP_HA_URL: ha.url,
    HAMCP_HA_USERS_TOKEN: USERS_TOKEN,
    HAMCP_LISTEN: '127.0.0.1:0',
    ...env,
  });
  if (!cli.handle) throw new Error(`server did not start: ${cli.lines.join('\n')}`);
  await until(() => cli.records().some((r) => r.msg === 'connected to Home Assistant'), 'HA connection');
  return { ...cli, url: `http://${cli.handle.address}/mcp` };
}

export async function connect(t: TestContext, url: string, key: string, era: (typeof ERAS)[number]) {
  const client = new Client(
    { name: 'test', version: '0.0.0' },
    { versionNegotiation: { mode: era === 'modern' ? { pin: '2026-07-28' } : 'legacy' } },
  );
  await client.connect(
    new StreamableHTTPClientTransport(new URL(url), {
      requestInit: { headers: { Authorization: `Bearer ${key}` } },
    }),
  );
  t.after(() => client.close());
  return client;
}

/** Parses the JSON text of a tool result. */
export function body(result: unknown): unknown {
  const { content } = result as { content: { type: string; text: string }[] };
  return JSON.parse(content[0]?.text ?? 'null');
}
