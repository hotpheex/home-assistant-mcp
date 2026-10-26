import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
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
  {
    entity_id: 'camera.porch',
    state: 'idle',
    attributes: { friendly_name: 'Porch', access_token: 'CAMSECRET', entity_picture: '/api/camera_proxy/camera.porch?token=CAMSECRET' },
  },
  {
    entity_id: 'media_player.den',
    state: 'playing',
    attributes: { friendly_name: 'Den Speaker', entity_picture: '/api/media_player_proxy/media_player.den?token=MEDIASECRET&cache=42' },
  },
];
/** The house's registries: the coffee maker is in an area through its device, and the lamp has an alias. */
export const REGISTRIES: Partial<FakeHaOptions> = {
  entities: [
    { entity_id: 'switch.coffee_maker', device_id: 'dev_coffee' },
    { entity_id: 'light.living_room', aliases: ['Sofa Light'] },
    { entity_id: 'lock.front_door', labels: ['security'] },
  ],
  devices: [{ id: 'dev_coffee', name: 'Coffee Maker', area_id: 'utility_room', labels: [] }],
  areas: [{ area_id: 'utility_room', name: 'Utility Room', floor_id: 'ground', aliases: [] }],
  labels: [{ label_id: 'security', name: 'Security' }],
  floors: [{ floor_id: 'ground', name: 'Ground Floor' }],
};

/** Admin-only content: configs and a helper with inline secrets, and runs whose trace holds a camera state and a password. */
export const CONFIGS: Partial<FakeHaOptions> = {
  configs: {
    'automation.porch_light': {
      id: 'porch_light_1',
      alias: 'Porch light at sunset',
      triggers: [{ trigger: 'sun', event: 'sunset' }],
      actions: [{ action: 'rest_command.notify', data: { api_key: 'CFGSECRET', url: 'https://bob:CFGSECRET@nas.local/hook' } }],
    },
    'script.morning': { alias: 'Morning', sequence: [{ action: 'rest_command.ping', data: { header: 'Bearer CFGSECRET1' } }] },
    'scene.movie_night': { id: 'movie_night_1', name: 'Movie night', entities: { 'media_player.den': { state: 'playing', password: 'SCENESECRET' } } },
  },
  helpers: { input_text: [{ id: 'wifi_password', name: 'Wifi password', initial: 'x', api_key: 'HELPERSECRET' }] },
  traces: ['run_1', 'run_2', 'run_3'].map((run_id, i) => ({
    domain: 'automation' as const,
    item_id: 'porch_light_1',
    run_id,
    state: 'stopped',
    script_execution: 'finished',
    last_step: 'action/0',
    timestamp: { start: `2026-10-2${i}T18:00:00+00:00`, finish: `2026-10-2${i}T18:00:01+00:00` },
    trigger: 'sunset',
    trace: {
      'trigger/0': [{ changed_variables: { trigger: { to_state: HOUSE.find((s) => s.entity_id === 'camera.porch') } } }],
      'action/0': [{ result: { params: { service_data: { password: 'TRACESECRET' } } } }],
    },
    config: { id: 'porch_light_1', alias: 'Porch light at sunset' },
    blueprint_inputs: null,
    context: { id: `ctx_${run_id}`, parent_id: null, user_id: null },
  })),
};

export function newKey() {
  const key = `hamcp_${randomBytes(32).toString('base64url')}`;
  return { key, sha256: createHash('sha256').update(key).digest('hex') };
}

export async function fakeHa(t: TestContext, options: Partial<FakeHaOptions> = {}) {
  const ha = await startFakeHa({
    users: { [USERS_TOKEN]: { is_admin: false }, [ADMIN_TOKEN]: { is_admin: true } },
    states: HOUSE,
    services: { light: { turn_on: { target: { entity: [{ domain: ['light'] }] } } } },
    ...REGISTRIES,
    ...CONFIGS,
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

export async function until(check: () => boolean, what: string, ms = 2000) {
  for (let i = 0; i < ms / 10 && !check(); i++) await new Promise((r) => setTimeout(r, 10));
  if (!check()) throw new Error(`timed out waiting for ${what}`);
}

/** Starts the server against `ha` and waits until every needed tier is connected and startup's warnings are logged. */
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
  await until(() => cli.records().some((r) => r.msg === 'startup warnings logged'), 'HA connection and startup warnings');
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

/**
 * Runs the built image as a deployer would, read-only and on the host network so it reaches HA on loopback.
 * Each stdout line is a log record, and `cleanup` registers the container's removal.
 */
export function runImage(image: string, policy: string, env: Record<string, string>, cleanup: (fn: () => void) => void) {
  const name = `hamcp-image-test-${randomBytes(4).toString('hex')}`;
  const settings = { HAMCP_POLICY: '/policy.yaml', HAMCP_LISTEN: '127.0.0.1:0', ...env };
  const args = Object.entries(settings).flatMap(([k, v]) => ['--env', `${k}=${v}`]);
  const container = spawn('docker', ['run', '--rm', '--name', name, '--read-only', '--network', 'host', '--volume', `${policy}:/policy.yaml:ro`, ...args, image], {
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  cleanup(() => spawnSync('docker', ['rm', '--force', name], { stdio: 'ignore' }));
  const records: Record<string, unknown>[] = [];
  createInterface({ input: container.stdout }).on('line', (line) => records.push(JSON.parse(line) as Record<string, unknown>));
  // 'close' rather than 'exit', so every stdout line is in by then.
  const exited = new Promise<number | null>((resolve) => container.on('close', resolve));
  const logged = (msg: string, ms = 60_000) => until(() => records.some((r) => r.msg === msg), msg, ms);
  return { name, records, exited, logged, url: () => `http://${String(records.find((r) => r.msg === 'listening')?.address)}/mcp` };
}
