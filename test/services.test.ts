import assert from 'node:assert/strict';
import { test, type TestContext } from 'node:test';
import type { FakeHaOptions, Registry } from './fake-ha.ts';
import { body, connect, fakeHa, newKey, startServer, USERS_TOKEN } from './harness.ts';

const entity = (entity_id: string, fields: Partial<Registry['entities'][number]> = {}) => ({
  entity_id,
  device_id: null,
  area_id: null,
  labels: [],
  hidden_by: null,
  disabled_by: null,
  entity_category: null,
  ...fields,
});
const device = (id: string, fields: Partial<Registry['devices'][number]> = {}) => ({ id, area_id: null, labels: [], parent_device_id: null, ...fields });

/** A house with each ADR 0008 case: area fallback, a labelled hub's child, a hidden entity and a config entity. */
const REGISTRY: Registry = {
  areas: [
    { area_id: 'kitchen', floor_id: 'ground', labels: [] },
    { area_id: 'living_room', floor_id: 'ground', labels: [] },
    { area_id: 'garage', floor_id: null, labels: [] },
  ],
  floors: [{ floor_id: 'ground' }],
  labels: [{ label_id: 'garden' }, { label_id: 'night' }],
  devices: [device('kitchen_light', { area_id: 'kitchen' }), device('hub', { labels: ['garden'] }), device('bulb', { parent_device_id: 'hub' }), device('garage_door', { area_id: 'garage' })],
  entities: [
    entity('light.kitchen', { device_id: 'kitchen_light' }),
    entity('button.kitchen_light_restart', { device_id: 'kitchen_light', entity_category: 'config' }),
    entity('light.kitchen_hidden', { area_id: 'kitchen', hidden_by: 'user' }),
    entity('switch.coffee_maker', { area_id: 'kitchen' }),
    entity('light.living_room', { area_id: 'living_room' }),
    entity('light.garden_bulb', { device_id: 'bulb' }),
    entity('lock.front_door', { labels: ['night'] }),
    entity('cover.garage_door', { device_id: 'garage_door' }),
  ],
};
const STATES = REGISTRY.entities.map((e) => ({ entity_id: e.entity_id, state: 'off', attributes: {} }));
const targeted = { target: { entity: [{}] } };
const SERVICES: FakeHaOptions['services'] = {
  light: { turn_on: { name: 'Turn on', fields: { brightness: { selector: { number: {} } } }, ...targeted }, turn_off: targeted },
  lock: { unlock: targeted },
  button: { press: targeted },
  switch: { turn_on: targeted },
  homeassistant: { turn_on: targeted },
  scene: { apply: { fields: { entities: {} } } },
  shell_command: { backup: { fields: {} } },
  rest_command: { ping: { fields: {}, response: { optional: false } } },
};

const agent = newKey();
async function serve(t: TestContext, rules: string, env: Record<string, string> = {}, options: Partial<FakeHaOptions> = {}) {
  const ha = await fakeHa(t, { states: STATES, registry: REGISTRY, services: SERVICES, ...options });
  const server = await startServer(t, `version: 1\ncallers:\n  agent:\n    keys: [{ sha256: ${agent.sha256} }]\n${rules}`, ha, env);
  const client = await connect(t, server.url, agent.key, 'modern');
  const before = ha.received.length;
  /** The commands sent since the client connected, without their ids. */
  const sent = () => ha.received.slice(before).map((r) => Object.fromEntries(Object.entries(r.message).filter(([k]) => k !== 'id')));
  const call = (args: Record<string, unknown>) => client.callTool({ name: 'ha_call_service', arguments: args });
  return { ha, server, client, sent, call };
}

test('an area Grant forwards exactly the entities HA expands the call target to', async (t) => {
  const { sent, call, ha } = await serve(t, 'grants:\n  - caller: agent\n    services: [light.turn_on]\n    targets: [{ area: kitchen }]\n');
  const result = await call({ domain: 'light', service: 'turn_on', target: { area_id: 'kitchen' }, data: { brightness: 40 } });
  assert.equal(result.isError, undefined);
  assert.deepEqual(body(result), { entity_ids: ['light.kitchen', 'switch.coffee_maker'], context_id: 'ctx-1' });
  assert.deepEqual(sent(), [
    { type: 'get_services' },
    { type: 'extract_from_target', target: { area_id: ['kitchen'] }, expand_group: false },
    { type: 'extract_from_target', target: { area_id: ['kitchen'] }, expand_group: false },
    { type: 'call_service', domain: 'light', service: 'turn_on', target: { entity_id: ['light.kitchen', 'switch.coffee_maker'] }, service_data: { brightness: 40 } },
  ]);
  assert.ok(ha.received.every((r) => r.token === USERS_TOKEN));
});

test('an allowed write is audited only with HAMCP_AUDIT_WRITES, by names only', async (t) => {
  const rules = 'grants:\n  - caller: agent\n    services: [light.turn_on]\n    targets: [{ area: kitchen }]\n';
  const args = { domain: 'light', service: 'turn_on', target: { area_id: 'kitchen' }, data: { brightness: 40 } };
  const quiet = await serve(t, rules);
  await quiet.call(args);
  assert.deepEqual(quiet.server.audits(), []);

  const audited = await serve(t, rules, { HAMCP_AUDIT_WRITES: 'true' });
  await audited.call(args);
  const [{ time, ...record } = {}] = audited.server.audits();
  assert.ok(time);
  assert.deepEqual(record, {
    audit: true,
    caller: 'agent',
    key_hash_prefix: agent.sha256.slice(0, 8),
    operation: 'service_call',
    tool: 'ha_call_service',
    service: 'light.turn_on',
    target: { area_id: ['kitchen'] },
    decision: 'allow',
    entities: ['light.kitchen', 'switch.coffee_maker'],
    grants: [0],
    context_id: 'ctx-1',
  });
});

const grantLights = 'grants:\n  - caller: agent\n    services: [light.turn_on]\n    targets: [{ domain: light }]\n';
const denied = (name: string, target: string) => `Denied: this Caller holds no Grant to call ${name} over ${target}. Do not retry this call.`;
const textOf = (result: unknown) => (result as { content: { text: string }[] }).content[0]?.text;

test('a service-call Grant lists ha_call_service with the plain-read tools', async (t) => {
  const { client } = await serve(t, grantLights);
  assert.deepEqual((await client.listTools()).tools.map((d) => d.name).sort(), ['ha_call_service', 'ha_get_states']);
});

test('a service no Grant names is refused before any outbound message', async (t) => {
  const { call, sent, server } = await serve(t, grantLights);
  const result = await call({ domain: 'lock', service: 'unlock', target: { entity_id: 'lock.front_door' } });
  assert.equal(result.isError, true);
  assert.equal(textOf(result), denied('lock.unlock', '{"entity_id":["lock.front_door"]}'));
  assert.deepEqual(sent(), []);
  const [{ time, ...record } = {}] = server.audits();
  assert.ok(time);
  assert.deepEqual(record, {
    audit: true,
    caller: 'agent',
    key_hash_prefix: agent.sha256.slice(0, 8),
    operation: 'service_call',
    tool: 'ha_call_service',
    service: 'lock.unlock',
    target: { entity_id: ['lock.front_door'] },
    decision: 'deny',
    grants: [],
    denies: [],
  });
});

test('one uncovered entity refuses the whole call, and only the audit line names it', async (t) => {
  const { call, sent, server } = await serve(t, grantLights);
  const result = await call({ domain: 'light', service: 'turn_on', target: { entity_id: ['light.kitchen'] }, data: { entity_id: 'lock.front_door' } });
  assert.equal(textOf(result), denied('light.turn_on', '{"entity_id":["light.kitchen","lock.front_door"]}'));
  assert.ok(!sent().some((m) => m.type === 'call_service'));
  const [record] = server.audits();
  assert.deepEqual([record?.decision, record?.entities, record?.uncovered, record?.denies], ['deny', ['light.kitchen', 'lock.front_door'], ['lock.front_door'], []]);
});

test('target keys in data are merged into the target, and only the checked entity_id list reaches HA', async (t) => {
  const { call, sent } = await serve(t, 'grants:\n  - caller: agent\n    services: [light.turn_on]\n    targets: [{ label: garden }]\n');
  const result = await call({ domain: 'light', service: 'turn_on', data: { label_id: 'garden', brightness: 5 } });
  assert.deepEqual(body(result), { entity_ids: ['light.garden_bulb'], context_id: 'ctx-1' });
  assert.deepEqual(sent().at(-1), { type: 'call_service', domain: 'light', service: 'turn_on', target: { entity_id: ['light.garden_bulb'] }, service_data: { brightness: 5 } });
});

test("a Deny on an area catches the config entities there, and the audit line names the Deny's index", async (t) => {
  const rules = `grants:
  - caller: agent
    services: [button.press]
    targets: [{ domain: button }]
denies:
  - caller: agent
    services: [light.turn_off]
  - caller: agent
    services: [button.press]
    targets: [{ area: kitchen }]
`;
  const { call, sent, server } = await serve(t, rules);
  const result = await call({ domain: 'button', service: 'press', target: { entity_id: 'button.kitchen_light_restart' } });
  assert.equal(textOf(result), denied('button.press', '{"entity_id":["button.kitchen_light_restart"]}'));
  assert.deepEqual(sent().filter((m) => m.type === 'extract_from_target').at(-1), {
    type: 'extract_from_target',
    target: { area_id: ['kitchen'] },
    expand_group: false,
    primary_entities_only: false,
  });
  assert.ok(!sent().some((m) => m.type === 'call_service'));
  assert.deepEqual(server.audits()[0]?.denies, [1]);
});

test('a Deny with no targets withholds its services before any outbound message', async (t) => {
  const { call, sent, server } = await serve(t, `${grantLights}denies:\n  - caller: agent\n    services: [light.*]\n`);
  const result = await call({ domain: 'light', service: 'turn_on', target: { entity_id: 'light.kitchen' } });
  assert.equal(textOf(result), denied('light.turn_on', '{"entity_id":["light.kitchen"]}'));
  assert.deepEqual(sent(), []);
  assert.deepEqual(server.audits()[0]?.denies, [0]);
});

test('entity_id all expands to the service domain, or to every entity for a delegating service', async (t) => {
  const rules = `grants:
  - caller: agent
    services: [light.turn_on]
    targets: [{ domain: light }]
  - caller: agent
    services: [homeassistant.turn_on]
    targets: [{ domain: light }, { domain: switch }]
`;
  const { call, server } = await serve(t, rules);
  assert.deepEqual(body(await call({ domain: 'light', service: 'turn_on', target: { entity_id: 'all' } })), {
    entity_ids: ['light.garden_bulb', 'light.kitchen', 'light.kitchen_hidden', 'light.living_room'],
    context_id: 'ctx-1',
  });
  const everything = await call({ domain: 'homeassistant', service: 'turn_on', data: { entity_id: 'all' } });
  assert.equal(textOf(everything), denied('homeassistant.turn_on', '{"entity_id":["all"]}'));
  assert.deepEqual(server.audits().at(-1)?.uncovered, ['button.kitchen_light_restart', 'cover.garage_door', 'lock.front_door']);
});

test('a target that resolves to nothing, or that HA cannot expand, is refused', async (t) => {
  const { call, sent } = await serve(t, 'grants:\n  - caller: agent\n    services: [light.turn_on]\n    targets: [{ area: kitchen }]\n');
  const result = await call({ domain: 'light', service: 'turn_on', target: { area_id: 'attic' } });
  assert.equal(result.isError, true);
  assert.equal(textOf(result), 'light.turn_on: target matches no entity.');
  const uuid = await call({ domain: 'light', service: 'turn_on', data: { entity_id: '0f3c2a9e8b7d4c1e' } });
  assert.equal(textOf(uuid), 'Home Assistant error: Entity ID 0f3c2a9e8b7d4c1e is an invalid entity ID');
  assert.ok(!sent().some((m) => m.type === 'call_service'));
});

test('a targetless service is checked by name and refuses a target; a targeted one needs a target', async (t) => {
  const { call, sent } = await serve(t, `${grantLights}  - caller: agent\n    services: [shell_command.backup]\n`);
  assert.deepEqual(body(await call({ domain: 'shell_command', service: 'backup' })), { entity_ids: [], context_id: 'ctx-1' });
  assert.deepEqual(sent().at(-1), { type: 'call_service', domain: 'shell_command', service: 'backup', service_data: {} });
  const before = sent().length;
  const withTarget = await call({ domain: 'shell_command', service: 'backup', data: { entity_id: 'light.kitchen' } });
  assert.equal(textOf(withTarget), 'shell_command.backup: this service takes no target.');
  assert.equal(textOf(await call({ domain: 'light', service: 'turn_on', data: { brightness: 3 } })), 'light.turn_on: this service needs a target.');
  assert.deepEqual(
    sent()
      .slice(before)
      .map((m) => m.type),
    ['get_services', 'get_services'],
  );
});

test('a service that responds returns its response; an oversize one is truncated with a marker, not refused', async (t) => {
  const responses = { 'rest_command.ping': { status: 200, content: 'pong' }, 'rest_command.dump': { content: 'x'.repeat(200_000) } };
  const services = { ...SERVICES, rest_command: { ping: { response: { optional: false } }, dump: { response: { optional: true } } } };
  const { call, sent } = await serve(t, 'grants:\n  - caller: agent\n    services: [rest_command.*]\n', {}, { services, responses });
  assert.deepEqual(body(await call({ domain: 'rest_command', service: 'ping' })), {
    entity_ids: [],
    context_id: 'ctx-1',
    response: { status: 200, content: 'pong' },
  });
  assert.equal(sent().at(-1)?.return_response, true);

  const dump = await call({ domain: 'rest_command', service: 'dump' });
  assert.equal(dump.isError, undefined);
  const truncated = textOf(dump) ?? '';
  assert.ok(Buffer.byteLength(truncated) <= 80_000);
  assert.ok(truncated.startsWith('{"entity_ids":[],"context_id":"ctx-2","response":{"content":"xxx'));
  assert.match(truncated, /\n\[truncated: the response was \d+ bytes, over the 80000-byte cap; the call ran\]$/);
});

test('"HA unavailable" when nothing was sent; "outcome unknown" when the connection drops after the call was sent', async (t) => {
  const { call, sent, ha } = await serve(t, grantLights);
  const args = { domain: 'light', service: 'turn_on', target: { entity_id: 'light.kitchen' } };
  ha.drop.add('call_service');
  const unknown = await call(args);
  assert.equal(unknown.isError, true);
  assert.equal(textOf(unknown), 'Outcome unknown: the connection to Home Assistant dropped after the call was sent. Check state before retrying.');
  assert.equal(sent().filter((m) => m.type === 'call_service').length, 1);

  await ha.outage();
  const unavailable = await call(args);
  assert.equal(textOf(unavailable), 'HA unavailable: nothing was sent to Home Assistant. Try again later.');
  assert.equal(sent().filter((m) => m.type === 'call_service').length, 1);
});

test('homeassistant services and scene.apply are covered only by exact name', async (t) => {
  const wildcard = await serve(t, 'grants:\n  - caller: agent\n    services: [scene.*, light.*]\n    targets: [{ domain: "*" }]\n');
  const apply = { domain: 'scene', service: 'apply', data: { entities: { 'lock.front_door': 'unlocked' } } };
  assert.equal(textOf(await wildcard.call(apply)), denied('scene.apply', 'no target'));
  assert.deepEqual(wildcard.sent(), []);
  const exact = await serve(t, 'grants:\n  - caller: agent\n    services: [scene.apply]\n');
  assert.equal((await exact.call(apply)).isError, undefined);
});
