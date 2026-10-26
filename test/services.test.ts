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
