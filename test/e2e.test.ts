import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { cpSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, suite, test, type TestContext } from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';
import { createConnection, createLongLivedTokenAuth, type Connection } from 'home-assistant-js-websocket';
import { body, connect, newKey, runImage, until, writePolicy } from './harness.ts';

/** The built image and the HA container image it runs against; CI sets both, and without them there is nothing to run. */
const image = process.env.HAMCP_IMAGE;
const haImage = process.env.HAMCP_HA_IMAGE;

const HA = 'http://127.0.0.1:8123';
const CLIENT_ID = `${HA}/`;
const canary = (where: string) => `hamcp-canary-${where}-${randomBytes(8).toString('hex')}`;
const SECRET_CANARY = canary('secrets-yaml');
const HEADER_CANARY = canary('rest-command');

/** HA's config directory: a secret behind `!secret` in an automation, a secret header on a rest_command, and the e2e house. */
const CONFIG = {
  'configuration.yaml': `homeassistant:
  name: hamcp e2e
automation: !include automations.yaml
# Apart from automations.yaml, whose config REST refuses to load a !secret.
automation canary:
  - id: canary
    alias: Canary
    triggers:
      - trigger: event
        event_type: hamcp_e2e_never
    actions:
      - event: hamcp_e2e_canary
        event_data:
          api_key: !secret canary_api_key
script: !include scripts.yaml
scene: !include scenes.yaml
history:
logbook:
hamcp_house:
rest_command:
  canary:
    url: ${HA}/manifest.json
    headers:
      authorization: Bearer ${HEADER_CANARY}
`,
  'secrets.yaml': `canary_api_key: ${SECRET_CANARY}\n`,
  'automations.yaml': '[]\n',
  'scripts.yaml': '{}\n',
  'scenes.yaml': '[]\n',
};

interface HaState {
  entity_id: string;
  attributes: Record<string, unknown>;
}

/** Polls a check that may throw while HA is still starting. */
async function eventually(check: () => Promise<boolean>, what: string, ms: number) {
  const end = Date.now() + ms;
  while (!(await check().catch(() => false))) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await sleep(1000);
  }
}

async function post(path: string, json: unknown): Promise<Record<string, unknown>> {
  const res = await fetch(`${HA}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(json) });
  if (!res.ok) throw new Error(`POST ${path}: ${res.status} ${await res.text()}`);
  return (await res.json()) as Record<string, unknown>;
}

async function accessToken(code: unknown) {
  const res = await fetch(`${HA}/auth/token`, {
    method: 'POST',
    body: new URLSearchParams({ grant_type: 'authorization_code', code: String(code), client_id: CLIENT_ID }),
  });
  if (!res.ok) throw new Error(`token: ${res.status} ${await res.text()}`);
  return ((await res.json()) as { access_token: string }).access_token;
}

/** Logs in through HA's login flow, as the frontend does. */
async function login(username: string, password: string) {
  const flow = await post('/auth/login_flow', { client_id: CLIENT_ID, handler: ['homeassistant', null], redirect_uri: CLIENT_ID });
  const done = await post(`/auth/login_flow/${String(flow.flow_id)}`, { client_id: CLIENT_ID, username, password });
  return accessToken(done.result);
}

const longLived = (conn: Connection, client_name: string) =>
  conn.sendMessagePromise<string>({ type: 'auth/long_lived_access_token', client_name, lifespan: 30 });

const reader = newKey();
const readerPolicy = writePolicy(`version: 1
callers:
  reader:
    keys:
      - sha256: ${reader.sha256}
grants:
  - caller: reader
    read: plain
`);

suite('the built image against a real HA', { skip: !(image && haImage) && 'HAMCP_IMAGE and HAMCP_HA_IMAGE are not set' }, () => {
  const cleanups: (() => void)[] = [];
  const cleanup = (fn: () => void) => cleanups.push(fn);
  let failed = false;
  const haName = `hamcp-e2e-ha-${randomBytes(4).toString('hex')}`;
  const operator = newKey();
  const expander = newKey();
  let owner: Connection;
  let agent: Connection;
  let adminToken: string;
  let revocableToken: string;
  let areaId: string;
  let server: ReturnType<typeof runImage>;

  /** Marks the run failed, so teardown prints HA's log. */
  const e2e = (name: string, fn: (t: TestContext) => Promise<void>) =>
    void test(name, { timeout: 180_000 }, async (t) => {
      await fn(t).catch((e: unknown) => {
        failed = true;
        throw e;
      });
    });

  before(
    async () => {
      const config = mkdtempSync(join(tmpdir(), 'hamcp-ha-'));
      for (const [file, text] of Object.entries(CONFIG)) writeFileSync(join(config, file), text);
      cpSync(new URL('ha/custom_components', import.meta.url), join(config, 'custom_components'), { recursive: true });
      const started = spawnSync('docker', ['run', '--detach', '--name', haName, '--network', 'host', '--volume', `${config}:/config`, haImage!], {
        encoding: 'utf8',
      });
      assert.equal(started.status, 0, started.stderr);
      cleanup(() => spawnSync('docker', ['rm', '--force', haName], { stdio: 'ignore' }));
      await eventually(async () => (await fetch(`${HA}/api/onboarding`)).ok, 'HA to serve', 300_000);

      // Onboarding: an admin owner, then a non-admin agent, each with long-lived tokens.
      const ownerPassword = randomBytes(16).toString('hex');
      const onboarded = await post('/api/onboarding/users', { client_id: CLIENT_ID, name: 'Owner', username: 'owner', password: ownerPassword, language: 'en' });
      owner = await createConnection({ auth: createLongLivedTokenAuth(HA, await accessToken(onboarded.auth_code)) });
      cleanup(() => owner.close());
      adminToken = await longLived(owner, 'hamcp-e2e-admin');
      const { user } = await owner.sendMessagePromise<{ user: { id: string } }>({ type: 'config/auth/create', name: 'Agent', group_ids: ['system-users'] });
      const agentPassword = randomBytes(16).toString('hex');
      await owner.sendMessagePromise({ type: 'config/auth_provider/homeassistant/create', user_id: user.id, username: 'agent', password: agentPassword });
      agent = await createConnection({ auth: createLongLivedTokenAuth(HA, await login('agent', agentPassword)) });
      cleanup(() => agent.close());
      const usersToken = await longLived(agent, 'hamcp-e2e-users');
      revocableToken = await longLived(agent, 'hamcp-e2e-revoked');

      // The house: the plug's device in an area, and the hub's device under a label.
      await eventually(
        async () => (await owner.sendMessagePromise<HaState[]>({ type: 'get_states' })).some((s) => s.entity_id === 'camera.e2e_camera'),
        'the e2e house',
        120_000,
      );
      const devices = await owner.sendMessagePromise<{ id: string; name: string }[]>({ type: 'config/device_registry/list' });
      const device = (name: string) => devices.find((d) => d.name === name)?.id;
      ({ area_id: areaId } = await owner.sendMessagePromise<{ area_id: string }>({ type: 'config/area_registry/create', name: 'E2E Room' }));
      const { label_id: labelId } = await owner.sendMessagePromise<{ label_id: string }>({ type: 'config/label_registry/create', name: 'E2E Hub' });
      await owner.sendMessagePromise({ type: 'config/device_registry/update', device_id: device('E2E Plug'), area_id: areaId });
      await owner.sendMessagePromise({ type: 'config/device_registry/update', device_id: device('E2E Hub'), labels: [labelId] });

      const policy = writePolicy(`version: 1
callers:
  operator:
    keys:
      - sha256: ${operator.sha256}
  expander:
    keys:
      - sha256: ${expander.sha256}
grants:
  - caller: operator
    read: config
  - caller: operator
    services: [rest_command.canary]
  - caller: operator
    services: [automation.trigger]
    targets:
      - domain: automation
  - caller: operator
    config_write: automation
  - caller: expander
    services: [switch.turn_on]
    targets:
      - label: ${labelId}
      - area: ${areaId}
  - caller: expander
    services: [button.press]
    targets:
      - domain: button
denies:
  - caller: expander
    services: [button.press]
    targets:
      - area: ${areaId}
`);
      server = runImage(image!, policy, { HAMCP_HA_URL: HA, HAMCP_HA_USERS_TOKEN: usersToken, HAMCP_HA_ADMIN_TOKEN: adminToken }, cleanup);
      await server.logged('startup warnings logged');
    },
    { timeout: 600_000 },
  );

  after(() => {
    if (failed) spawnSync('docker', ['logs', '--tail', '300', haName], { stdio: ['ignore', 'inherit', 'inherit'] });
    for (const fn of cleanups.reverse()) fn();
  });

  e2e('each of the ten tools runs once, and no canary appears in any byte they return', async (t) => {
    // Each canary sits in what HA itself returns, so only the server keeps it out.
    const tokens = new Set<string>();
    const collectTokens = async () => {
      for (const s of await owner.sendMessagePromise<HaState[]>({ type: 'get_states' })) {
        if (['camera.e2e_camera', 'image.e2e_image'].includes(s.entity_id)) tokens.add(String(s.attributes.access_token));
      }
    };
    await collectTokens();
    assert.equal(tokens.size, 2, 'the camera and the image each carry a bearer token');
    assert.match(JSON.stringify(await owner.sendMessagePromise({ type: 'automation/config', entity_id: 'automation.canary' })), new RegExp(SECRET_CANARY));

    const client = await connect(t, server.url(), operator.key, 'modern');
    const returned: string[] = [];
    const call = async (name: string, args: Record<string, unknown>) => {
      const result = await client.callTool({ name, arguments: args });
      returned.push(JSON.stringify(result));
      assert.ok(!result.isError, `${name}: ${JSON.stringify(result.content)}`);
      return body(result) as Record<string, unknown>;
    };
    const listed = <T>(value: unknown) => value as T[];

    const states = await call('ha_get_states', { full: true });
    assert.ok(listed<HaState>(states.states).some((s) => s.entity_id === 'camera.e2e_camera'));
    await call('ha_get_history', { entity_ids: ['camera.e2e_camera', 'switch.e2e_plug'] });
    await call('ha_get_logbook', {});
    const devices = await call('ha_get_registry', { registry: 'device', query: 'E2E' });
    assert.ok(Number(devices.total) >= 2);
    const services = await call('ha_list_services', { domain: 'rest_command' });
    assert.equal(listed<{ service: string; callable: boolean }>(services.services).find((s) => s.service === 'rest_command.canary')?.callable, true);
    const rest = await call('ha_call_service', { domain: 'rest_command', service: 'canary' });
    assert.equal((rest.response as { status: number }).status, 200);
    await call('ha_call_service', { domain: 'automation', service: 'trigger', target: { entity_id: 'automation.canary' } });
    const config = await call('ha_get_config', { kind: 'automation', entity_id: 'automation.canary' });
    assert.match(JSON.stringify(config), /"api_key":"\*\*REDACTED\*\*"/);
    let traces: { run_id: string }[] = [];
    await eventually(async () => (traces = listed<{ run_id: string }>((await call('ha_list_traces', { kind: 'automation', id: 'canary' })).traces)).length > 0, 'a trace', 30_000);
    await call('ha_get_trace', { kind: 'automation', id: 'canary', run_id: traces[0]!.run_id, sections: ['trace', 'config', 'context'] });
    await call('ha_write_config', {
      kind: 'automation',
      action: 'create',
      id: 'e2e_written',
      config: { alias: 'Written by the e2e', triggers: [{ trigger: 'event', event_type: 'hamcp_e2e_never' }], actions: [{ event: 'hamcp_e2e_written' }] },
    });

    await collectTokens();
    const canaries = [SECRET_CANARY, HEADER_CANARY, ...tokens];
    assert.deepEqual(
      canaries.filter((c) => returned.some((r) => r.includes(c))),
      [],
    );
  });

  e2e('a config write that carries the Redaction marker is refused, and HA keeps the real value', async (t) => {
    const client = await connect(t, server.url(), operator.key, 'modern');
    const read = body(await client.callTool({ name: 'ha_get_config', arguments: { kind: 'automation', entity_id: 'automation.canary' } })) as { config: object };
    const write = await client.callTool({ name: 'ha_write_config', arguments: { kind: 'automation', action: 'update', id: 'canary', config: read.config } });
    assert.ok(write.isError);
    assert.match(JSON.stringify(write.content), /redacted value at actions\[0\]\.event_data\.api_key/);
    assert.match(JSON.stringify(await owner.sendMessagePromise({ type: 'automation/config', entity_id: 'automation.canary' })), new RegExp(SECRET_CANARY));
  });

  e2e("a service call's Targets mean HA's own expansion (ADR 0008)", async (t) => {
    const client = await connect(t, server.url(), expander.key, 'modern');
    const audits = () => server.records.filter((r) => r.audit === true);
    const call = async (name: string, target: Record<string, unknown>) => {
      const seen = audits().length;
      const [domain, service] = name.split('.');
      const result = await client.callTool({ name: 'ha_call_service', arguments: { domain, service, target } });
      if (result.isError) await until(() => audits().length > seen, 'the denial audit line', 5000);
      const audit = audits().at(-1);
      // A refusal shows up whole in a failed assertion on `acted`.
      return { result, audit, acted: result.isError ? { refused: result.content, audit } : (body(result) as { entity_ids: string[] }).entity_ids.sort() };
    };

    t.diagnostic(JSON.stringify(await owner.sendMessagePromise({ type: 'config/device_registry/list' })));
    t.diagnostic(JSON.stringify(await owner.sendMessagePromise({ type: 'config/entity_registry/list' })));
    t.diagnostic(JSON.stringify(await owner.sendMessagePromise({ type: 'config/label_registry/list' })));
    t.diagnostic(JSON.stringify(await owner.sendMessagePromise({ type: 'extract_from_target', target: { label_id: ['e2e_hub'] }, expand_group: false })));
    // A labelled hub's child devices are covered by the label.
    assert.deepEqual((await call('switch.turn_on', { entity_id: ['switch.outlet_a', 'switch.outlet_b'] })).acted, ['switch.outlet_a', 'switch.outlet_b']);
    // The area holds the plug's primary switch, but neither its hidden nor its config entity...
    assert.deepEqual((await call('switch.turn_on', { area_id: areaId })).acted, ['switch.e2e_plug']);
    // ...so the area Grant covers neither.
    for (const entity of ['switch.e2e_plug_led', 'switch.e2e_plug_child_lock']) {
      const { result, audit } = await call('switch.turn_on', { entity_id: entity });
      assert.ok(result.isError, entity);
      assert.deepEqual(audit?.uncovered, [entity]);
    }
    // An area Deny reaches the plug's config button, which the domain Grant covers.
    const { result, audit } = await call('button.press', { entity_id: 'button.e2e_plug_restart' });
    assert.ok(result.isError);
    assert.deepEqual([audit?.uncovered, audit?.denies], [[], [0]]);
  });

  e2e('startup refuses a users-tier token that belongs to an HA admin', async (t) => {
    const refused = runImage(image!, readerPolicy, { HAMCP_HA_URL: HA, HAMCP_HA_USERS_TOKEN: adminToken }, (fn) => t.after(fn));
    assert.equal(await refused.exited, 1);
    assert.ok(refused.records.some((r) => r.level === 'error' && /belongs to an HA admin/.test(String(r.msg))));
  });

  e2e('the server exits when its users-tier token is revoked while it runs', async (t) => {
    const running = runImage(image!, readerPolicy, { HAMCP_HA_URL: HA, HAMCP_HA_USERS_TOKEN: revocableToken }, (fn) => t.after(fn));
    await running.logged('connected to Home Assistant');
    const tokens = await agent.sendMessagePromise<{ id: string; client_name: string | null }[]>({ type: 'auth/refresh_tokens' });
    await agent.sendMessagePromise({ type: 'auth/delete_refresh_token', refresh_token_id: tokens.find((r) => r.client_name === 'hamcp-e2e-revoked')?.id });
    assert.equal(await running.exited, 1);
    assert.ok(running.records.some((r) => r.level === 'error' && /rejected the users-tier token/.test(String(r.msg))));
  });
});
