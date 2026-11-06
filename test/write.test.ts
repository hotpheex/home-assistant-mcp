import assert from 'node:assert/strict';
import type { TestContext } from 'node:test';
import { test } from 'node:test';
import { REDACTED as M } from '../src/redaction.ts';
import { ADMIN_TOKEN, adminCaller, body, connect, DASHBOARDS, fakeHa, newKey, policyOf, REGISTRIES, startServer, until } from './harness.ts';

const keys = Object.fromEntries(['auditor', 'automator', 'scripter', 'scener', 'helperer', 'dasher'].map((name) => [name, newKey()]));
const policy = policyOf(
  keys,
  `grants:
  - caller: auditor
    read: config
  - caller: automator
    config_write: automation
  - caller: scripter
    config_write: script
  - caller: scener
    config_write: scene
  - caller: helperer
    config_write: helper
  - caller: dasher
    config_write: dashboard
`,
);

async function house(t: TestContext) {
  const ha = await fakeHa(t);
  const server = await startServer(t, policy, ha, { HAMCP_HA_ADMIN_TOKEN: ADMIN_TOKEN, HAMCP_AUDIT_WRITES: 'true' });
  const as = async (who: string) => {
    const client = await connect(t, server.url, keys[who]!.key, 'modern');
    return { client, call: adminCaller(ha, client) };
  };
  return { ha, server, as };
}

const NEW_AUTOMATION = { alias: 'Hall light', triggers: [{ trigger: 'sun', event: 'sunset' }], actions: [{ action: 'light.turn_on' }] };

test('a config-write Grant lists ha_write_config, described as admin-equivalent; config read lists only the config-read tools', async (t) => {
  const { as } = await house(t);
  const listed = (await (await as('automator')).client.listTools()).tools;
  assert.match(listed.find((d) => d.name === 'ha_write_config')?.description ?? '', /admin-equivalent/);
  const auditing = (await (await as('auditor')).client.listTools()).tools;
  assert.deepEqual(auditing.map((d) => d.name), ['ha_get_config', 'ha_list_traces', 'ha_get_trace', 'ha_get_logs', 'ha_list_blueprints']);
});

test('an automation create posts the config to HA, and the allowed write is audited by name only', async (t) => {
  const { ha, server, as } = await house(t);
  const { call } = await as('automator');
  const created = await call('ha_write_config', { kind: 'automation', action: 'create', id: 'hall_light', config: NEW_AUTOMATION });
  assert.equal(created.result.isError, undefined);
  assert.deepEqual(created.sent, [
    { type: 'GET /api/config/automation/config/hall_light' },
    { type: 'POST /api/config/automation/config/hall_light', body: NEW_AUTOMATION },
  ]);
  assert.deepEqual(Object.values(ha.configs).find((c) => c.id === 'hall_light'), { id: 'hall_light', ...NEW_AUTOMATION });
  assert.deepEqual(body(created.result), { kind: 'automation', action: 'create', id: 'hall_light', result: { result: 'ok' } });

  const who = { time: undefined, audit: true, caller: 'automator', key_hash_prefix: keys.automator!.sha256.slice(0, 8), operation: 'config_write', tool: 'ha_write_config' };
  const name = { kind: 'automation', action: 'create', id: 'hall_light' };
  assert.deepEqual(
    server.audits().map((a) => ({ ...a, time: undefined })),
    [
      { ...who, ...name, decision: 'allow', grants: [1] },
      { ...who, ...name, outcome: 'done' },
    ],
  );
});

test('an update merges its top-level keys into the stored config, since HA replaces the whole entry', async (t) => {
  const { ha, server, as } = await house(t);
  const { call } = await as('automator');
  const updated = await call('ha_write_config', { kind: 'automation', action: 'update', id: 'porch_light_1', config: { alias: 'Porch light at dusk' } });
  assert.equal(updated.result.isError, undefined);
  const stored = {
    id: 'porch_light_1',
    alias: 'Porch light at dusk',
    triggers: [{ trigger: 'sun', event: 'sunset' }],
    actions: [{ action: 'rest_command.notify', data: { api_key: 'CFGSECRET', url: 'https://bob:CFGSECRET@nas.local/hook' } }],
  };
  assert.deepEqual(updated.sent, [
    { type: 'GET /api/config/automation/config/porch_light_1' },
    { type: 'POST /api/config/automation/config/porch_light_1', body: stored },
  ]);
  assert.deepEqual(ha.configs['automation.porch_light'], stored);

  const missing = await call('ha_write_config', { kind: 'automation', action: 'update', id: 'nope', config: { alias: 'x' } });
  assert.match(JSON.stringify(missing.result.content), /does not exist/);
  const existing = await call('ha_write_config', { kind: 'automation', action: 'create', id: 'porch_light_1', config: NEW_AUTOMATION });
  assert.match(JSON.stringify(existing.result.content), /already exists/);
  for (const refused of [missing, existing]) assert.deepEqual(refused.sent.map((s) => String(s.type)).filter((type) => !type.startsWith('GET ')), []);

  const invalid = await call('ha_write_config', { kind: 'automation', action: 'create', id: 'bare', config: { alias: 'No triggers' } });
  assert.equal(invalid.result.isError, true);
  assert.match(JSON.stringify(invalid.result.content), /Home Assistant refused the request: Message malformed: required key not provided/);
  assert.deepEqual(
    server.audits().map((a) => [a.id, a.decision, a.outcome]),
    [['porch_light_1', 'allow', undefined], ['porch_light_1', undefined, 'done'], ['nope', 'allow', undefined], ['porch_light_1', 'allow', undefined], ['bare', 'allow', undefined]],
  );
  assert.doesNotMatch(JSON.stringify(server.audits()), /malformed|required key|Porch light at dusk/);
});

test('deletes, and script and scene writes, go to their own config endpoints', async (t) => {
  const { ha, server, as } = await house(t);
  const automator = await as('automator');
  const deleted = await automator.call('ha_write_config', { kind: 'automation', action: 'delete', id: 'porch_light_1' });
  assert.deepEqual(deleted.sent, [{ type: 'DELETE /api/config/automation/config/porch_light_1' }]);
  assert.equal(ha.configs['automation.porch_light'], undefined);
  const gone = await automator.call('ha_write_config', { kind: 'automation', action: 'delete', id: 'porch_light_1' });
  assert.match(JSON.stringify(gone.result.content), /Resource not found/);

  const script = await (await as('scripter')).call('ha_write_config', { kind: 'script', action: 'update', id: 'morning', config: { alias: 'Early' } });
  assert.deepEqual(script.sent.map((s) => s.type), ['GET /api/config/script/config/morning', 'POST /api/config/script/config/morning']);
  assert.equal(ha.configs['script.morning']?.alias, 'Early');

  const scene = { name: 'Reading', entities: { 'light.living_room': { state: 'on' } } };
  const created = await (await as('scener')).call('ha_write_config', { kind: 'scene', action: 'create', id: 'reading', config: scene });
  assert.deepEqual(created.sent.at(-1), { type: 'POST /api/config/scene/config/reading', body: scene });
  assert.deepEqual(
    server.audits().map((a) => [a.kind, a.action, a.decision ?? a.outcome]),
    [['automation', 'delete', 'allow'], ['automation', 'delete', 'done'], ['automation', 'delete', 'allow'], ['script', 'update', 'allow'], ['script', 'update', 'done'], ['scene', 'create', 'allow'], ['scene', 'create', 'done']],
  );
});

test('a config write of a kind the Caller does not hold is refused and audited, with nothing sent', async (t) => {
  const { server, as } = await house(t);
  const { call } = await as('scripter');
  const denied = await call('ha_write_config', { kind: 'automation', action: 'create', id: 'sneaky', config: NEW_AUTOMATION });
  assert.equal(denied.result.isError, true);
  assert.match(JSON.stringify(denied.result.content), /no Grant for config writes of automation\. Do not retry/);
  assert.deepEqual(denied.sent, []);
  const [audit] = server.audits().filter((a) => a.caller === 'scripter');
  assert.deepEqual([audit?.decision, audit?.operation, audit?.kind, audit?.action, audit?.id, audit?.grants], ['deny', 'config_write', 'automation', 'create', 'sneaky', []]);
  assert.doesNotMatch(JSON.stringify(server.audits()), /Hall light|triggers/, 'audit lines carry names, never bodies');
});

test('helper writes go through the helper domain WebSocket commands; an update sends the stored helper with its keys merged over it', async (t) => {
  const { ha, server, as } = await house(t);
  const { call } = await as('helperer');
  const created = await call('ha_write_config', { kind: 'helper', action: 'create', id: 'input_boolean.guest_mode', config: { name: 'Guest mode' } });
  assert.deepEqual(created.sent, [{ type: 'input_boolean/create', name: 'Guest mode' }]);
  assert.deepEqual(body(created.result), { kind: 'helper', action: 'create', id: 'input_boolean.guest_mode', result: { id: 'guest_mode', name: 'Guest mode' } });

  // HA replaces a helper on update, so a partial update would reset step and mode and drop the unit.
  const thermostat = { name: 'Target temp', min: 10, max: 30, step: 0.5, mode: 'box', unit_of_measurement: '°C', icon: 'mdi:thermometer' };
  await call('ha_write_config', { kind: 'helper', action: 'create', id: 'input_number.target_temp', config: thermostat });
  const icon = await call('ha_write_config', { kind: 'helper', action: 'update', id: 'input_number.target_temp', config: { icon: 'mdi:fire' } });
  assert.deepEqual(icon.sent, [{ type: 'input_number/list' }, { type: 'input_number/update', ...thermostat, icon: 'mdi:fire', input_number_id: 'target_temp' }]);
  assert.deepEqual(ha.helpers.input_number, [{ id: 'target_temp', ...thermostat, icon: 'mdi:fire' }]);

  await call('ha_write_config', { kind: 'helper', action: 'create', id: 'timer.tea', config: { name: 'Tea', duration: '0:04:00', restore: true } });
  await call('ha_write_config', { kind: 'helper', action: 'update', id: 'timer.tea', config: { name: 'Green tea' } });
  assert.deepEqual(ha.helpers.timer, [{ id: 'tea', name: 'Green tea', duration: '0:04:00', restore: true }]);
  const extra = await call('ha_write_config', { kind: 'helper', action: 'update', id: 'timer.tea', config: { colour: 'green' } });
  assert.match(JSON.stringify(extra.result.content), /Home Assistant refused the request: extra keys not allowed @ data\['colour'\]/);

  const updated = await call('ha_write_config', { kind: 'helper', action: 'update', id: 'input_text.nas_url', config: { icon: 'mdi:nas' } });
  const stored = { id: 'nas_url', name: 'NAS URL', initial: 'https://bob:HELPERSECRET@nas.local', icon: 'mdi:nas', min: 0, max: 100, mode: 'text' };
  assert.deepEqual(ha.helpers.input_text, [stored]);
  assert.deepEqual(body(updated.result), { kind: 'helper', action: 'update', id: 'input_text.nas_url', result: { ...stored, initial: `https://${M}@nas.local` } });

  const deleted = await call('ha_write_config', { kind: 'helper', action: 'delete', id: 'input_boolean.guest_mode' });
  assert.deepEqual(deleted.sent, [{ type: 'input_boolean/delete', input_boolean_id: 'guest_mode' }]);
  const unknown = await call('ha_write_config', { kind: 'helper', action: 'update', id: 'timer.nope', config: { duration: '00:01:00' } });
  assert.match(JSON.stringify(unknown.result.content), /The helper timer\.nope does not exist; create it instead/);
  assert.deepEqual(unknown.sent, [{ type: 'timer/list' }]);

  const person = await call('ha_write_config', { kind: 'helper', action: 'delete', id: 'person.bob' });
  assert.match(JSON.stringify(person.result.content), /id: must be <helper domain>\.<id>/);
  assert.deepEqual(person.sent, []);
  assert.deepEqual(
    server.audits().map((a) => [a.action, a.id, a.decision ?? a.outcome]),
    [
      ['create', 'input_boolean.guest_mode', 'allow'], ['create', 'input_boolean.guest_mode', 'done'],
      ['create', 'input_number.target_temp', 'allow'], ['create', 'input_number.target_temp', 'done'],
      ['update', 'input_number.target_temp', 'allow'], ['update', 'input_number.target_temp', 'done'],
      ['create', 'timer.tea', 'allow'], ['create', 'timer.tea', 'done'],
      ['update', 'timer.tea', 'allow'], ['update', 'timer.tea', 'done'], ['update', 'timer.tea', 'allow'],
      ['update', 'input_text.nas_url', 'allow'], ['update', 'input_text.nas_url', 'done'],
      ['delete', 'input_boolean.guest_mode', 'allow'], ['delete', 'input_boolean.guest_mode', 'done'],
      ['update', 'timer.nope', 'allow'],
    ],
  );
});

test('a config carrying the Redaction marker is refused with its path, audited by name, and nothing is sent', async (t) => {
  const { server, as } = await house(t);
  const automator = await as('automator');
  const masked = { actions: [{ action: 'rest_command.notify', data: { api_key: M } }] };
  const update = await automator.call('ha_write_config', { kind: 'automation', action: 'update', id: 'porch_light_1', config: masked });
  assert.equal(update.result.isError, true);
  assert.match(JSON.stringify(update.result.content), /config carries a redacted value at actions\[0\]\.data\.api_key/);
  assert.deepEqual(update.sent, []);

  const helper = await (await as('helperer')).call('ha_write_config', {
    kind: 'helper',
    action: 'create',
    id: 'input_text.nas',
    config: { name: 'NAS', initial: `https://${M}@nas.local` },
  });
  assert.match(JSON.stringify(helper.result.content), /config carries a redacted value at initial/);
  assert.deepEqual(helper.sent, []);
  assert.deepEqual(
    server.audits().map((a) => ({ ...a, time: undefined })),
    [
      { time: undefined, audit: true, caller: 'automator', key_hash_prefix: keys.automator!.sha256.slice(0, 8), operation: 'config_write', tool: 'ha_write_config', kind: 'automation', action: 'update', id: 'porch_light_1', decision: 'deny', reason: 'config carries a redacted value' },
      { time: undefined, audit: true, caller: 'helperer', key_hash_prefix: keys.helperer!.sha256.slice(0, 8), operation: 'config_write', tool: 'ha_write_config', kind: 'helper', action: 'create', id: 'input_text.nas', decision: 'deny', reason: 'config carries a redacted value' },
    ],
  );
});

test('ha_get_config serves scene and helper config, masked, only to a Caller that writes that kind', async (t) => {
  const { server, as } = await house(t);
  const scener = await as('scener');
  const scene = await scener.call('ha_get_config', { kind: 'scene', id: 'movie_night_1' });
  assert.deepEqual(scene.sent, [{ type: 'GET /api/config/scene/config/movie_night_1' }]);
  const picture = '/api/media_player_proxy/media_player.den';
  assert.deepEqual(body(scene.result), { config: { id: 'movie_night_1', name: 'Movie night', entities: { 'media_player.den': { state: 'playing', password: M, entity_picture: picture } } } });
  assert.match(JSON.stringify((await scener.call('ha_get_config', { kind: 'scene', id: 'nope' })).result.content), /Scene nope not found/);

  const helperer = await as('helperer');
  const helper = await helperer.call('ha_get_config', { kind: 'helper', id: 'input_text.nas_url' });
  assert.deepEqual(helper.sent, [{ type: 'input_text/list' }]);
  assert.deepEqual(body(helper.result), { config: { id: 'nas_url', name: 'NAS URL', initial: `https://${M}@nas.local` } });
  const automation = await helperer.call('ha_get_config', { kind: 'automation', entity_id: 'automation.porch_light' });
  assert.equal(automation.result.isError, undefined, 'any config write gives automation and script config read');
  const noId = await helperer.call('ha_get_config', { kind: 'helper', entity_id: 'input_text.nas_url' });
  assert.match(JSON.stringify(noId.result.content), /id: is required for a helper/);
  const extraEntity = await scener.call('ha_get_config', { kind: 'scene', id: 'movie_night_1', entity_id: 'scene.movie_night' });
  assert.match(JSON.stringify(extraEntity.result.content), /entity_id: is not taken for a scene, which takes only id/);
  assert.deepEqual(extraEntity.sent, []);

  for (const [who, args] of [
    ['auditor', { kind: 'scene', id: 'movie_night_1' }],
    ['auditor', { kind: 'helper', id: 'input_text.nas_url' }],
    ['automator', { kind: 'scene', id: 'movie_night_1' }],
  ] as const) {
    const denied = await (await as(who)).call('ha_get_config', args);
    assert.match(JSON.stringify(denied.result.content), new RegExp(`no Grant for ${args.kind} config\\. Do not retry`));
    assert.deepEqual(denied.sent, []);
  }
  assert.deepEqual(
    server.audits().filter((a) => a.decision === 'deny').map((a) => [a.caller, a.operation, a.kind]),
    [['auditor', 'config_read', 'scene'], ['auditor', 'config_read', 'helper'], ['automator', 'config_read', 'scene']],
  );
});

test('a config write dropped or left unanswered after it was sent reports outcome unknown; an unanswered read, HA unavailable', async (t) => {
  t.mock.timers.enable({ apis: ['setInterval'] });
  const { ha, as } = await house(t);
  const { call, client } = await as('automator');
  ha.drop.add('POST /api/config/automation/config/hall_light');
  const dropped = await call('ha_write_config', { kind: 'automation', action: 'create', id: 'hall_light', config: NEW_AUTOMATION });
  assert.equal(dropped.result.isError, true);
  assert.match(JSON.stringify(dropped.result.content), /Outcome unknown/);

  // A REST request still unanswered a whole heartbeat beat after one saw it is abandoned.
  const scripter = (await as('scripter')).client;
  ha.hang();
  const deleted = client.callTool({ name: 'ha_write_config', arguments: { kind: 'automation', action: 'delete', id: 'porch_light_1' } });
  const updated = scripter.callTool({ name: 'ha_write_config', arguments: { kind: 'script', action: 'update', id: 'morning', config: { alias: 'Early' } } });
  const types = () => ha.received.map((r) => r.message.type);
  await until(() => types().includes('DELETE /api/config/automation/config/porch_light_1') && types().includes('GET /api/config/script/config/morning'), 'both requests to reach HA');
  t.mock.timers.tick(30_000);
  t.mock.timers.tick(30_000);
  assert.match(JSON.stringify((await deleted).content), /Outcome unknown/);
  assert.equal(((await updated).content as { text: string }[])[0]?.text, 'HA unavailable: Home Assistant did not answer. Try again later.');
  assert.ok(!types().includes('POST /api/config/script/config/morning'));
});

const namers = Object.fromEntries(['namer', 'helper_writer'].map((name) => [name, newKey()]));
async function registry(t: TestContext, env: Record<string, string> = { HAMCP_AUDIT_WRITES: 'true' }) {
  const ha = await fakeHa(t);
  const rules = 'grants:\n  - caller: namer\n    config_write: entity_name\n  - caller: helper_writer\n    config_write: helper\n';
  const server = await startServer(t, policyOf(namers, rules), ha, { HAMCP_HA_ADMIN_TOKEN: ADMIN_TOKEN, ...env });
  const as = async (who: string) => adminCaller(ha, await connect(t, server.url, namers[who]!.key, 'modern'));
  return { ha, server, as };
}

test('an entity_name update sends only its name, icon or aliases to the entity registry, audited by entity_id', async (t) => {
  const { ha, server, as } = await registry(t);
  const call = await as('namer');
  const changes = [{ name: 'Espresso' }, { icon: 'mdi:coffee' }, { aliases: ['Coffee', 'Barista'] }];
  for (const config of changes) {
    const written = await call('ha_write_config', { kind: 'entity_name', action: 'update', id: 'switch.coffee_maker', config });
    assert.equal(written.result.isError, undefined);
    assert.deepEqual(written.sent, [{ type: 'config/entity_registry/update', entity_id: 'switch.coffee_maker', ...config }]);
  }
  const renamed = await call('ha_write_config', { kind: 'entity_name', action: 'update', id: 'switch.coffee_maker', config: { name: null, icon: null } });
  assert.deepEqual(body(renamed.result), {
    kind: 'entity_name',
    action: 'update',
    id: 'switch.coffee_maker',
    result: { entity_entry: { entity_id: 'switch.coffee_maker', name: null, icon: null, device_id: 'dev_coffee', area_id: null, labels: [], hidden_by: null, disabled_by: null, entity_category: null, aliases: ['Coffee', 'Barista'] } },
  });
  const missing = await call('ha_write_config', { kind: 'entity_name', action: 'update', id: 'switch.nope', config: { name: 'x' } });
  assert.match(JSON.stringify(missing.result.content), /Home Assistant refused the request: Entity not found/);
  assert.deepEqual(REGISTRIES.entities?.[0], { entity_id: 'switch.coffee_maker', device_id: 'dev_coffee' }, "the fake's seed registry is not changed");
  assert.deepEqual(
    server.audits().map((a) => [a.kind, a.action, a.id, a.decision ?? a.outcome]),
    [...changes, {}].flatMap(() => [['entity_name', 'update', 'switch.coffee_maker', 'allow'], ['entity_name', 'update', 'switch.coffee_maker', 'done']]).concat([['entity_name', 'update', 'switch.nope', 'allow']]),
  );
  assert.doesNotMatch(JSON.stringify(server.audits()), /Espresso|Barista|mdi:coffee/);
  assert.equal(ha.received.filter((r) => r.message.type === 'config/entity_registry/update').length, 5);
});

test('an entity_name write is refused, with nothing sent, for any other registry field (audited), for create or delete, and for a Caller holding another kind', async (t) => {
  const { ha, server, as } = await registry(t, {});
  const call = await as('namer');
  const update = { kind: 'entity_name', action: 'update', id: 'lock.front_door' };
  for (const field of [{ area_id: 'garage' }, { labels: [] }, { hidden_by: 'user' }, { disabled_by: 'user' }, { new_entity_id: 'lock.back_door' }]) {
    const refused = await call('ha_write_config', { ...update, config: { name: 'Front', ...field } });
    assert.match(JSON.stringify(refused.result.content), new RegExp(`Denied: entity_name changes only name, icon and aliases, not config\\.${Object.keys(field)[0]}\\. Nothing was sent`));
    assert.deepEqual(refused.sent, []);
  }
  const create = await call('ha_write_config', { ...update, action: 'create', config: { name: 'Front' } });
  assert.match(JSON.stringify(create.result.content), /action: entity_name takes only update/);
  const remove = await call('ha_write_config', { ...update, action: 'delete' });
  assert.match(JSON.stringify(remove.result.content), /action: entity_name takes only update/);
  const notEntity = await call('ha_write_config', { ...update, id: 'front_door', config: { name: 'Front' } });
  assert.match(JSON.stringify(notEntity.result.content), /id: must be an entity_id/);
  const read = await call('ha_get_config', { kind: 'entity_name', id: 'lock.front_door' });
  assert.match(JSON.stringify(read.result.content), /kind: entity_name has no config to read; ha_get_registry lists each entity's name and icon/);

  const other = await as('helper_writer');
  const denied = await other('ha_write_config', { ...update, config: { aliases: ['Garage'] } });
  assert.match(JSON.stringify(denied.result.content), /no Grant for config writes of entity_name\. Do not retry/);
  assert.equal(ha.received.filter((r) => r.message.type === 'config/entity_registry/update').length, 0);

  const allowed = await call('ha_write_config', { ...update, config: { aliases: ['Front'] } });
  assert.equal(allowed.result.isError, undefined);
  const field = ['namer', 'entity_name', 'lock.front_door', 'deny', 'entity_name changes only name, icon and aliases'];
  assert.deepEqual(
    server.audits().map((a) => [a.caller, a.kind, a.id, a.decision, a.reason]),
    [field, field, field, field, field, ['helper_writer', 'entity_name', 'lock.front_door', 'deny', undefined]],
    'only refusals are audited, since writes are audited on opt-in',
  );
  assert.doesNotMatch(JSON.stringify(server.audits()), /garage|back_door|Front/, 'audit lines carry names, never config');
});

test('zone writes share the helper path: zone WebSocket commands, an update merged over the stored zone, config served only to a zone writer', async (t) => {
  const people = { zoner: newKey(), helperer: newKey() };
  const ha = await fakeHa(t);
  const zonePolicy = policyOf(people, 'grants:\n  - caller: zoner\n    config_write: zone\n  - caller: helperer\n    config_write: helper\n');
  const server = await startServer(t, zonePolicy, ha, { HAMCP_HA_ADMIN_TOKEN: ADMIN_TOKEN, HAMCP_AUDIT_WRITES: 'true' });
  const call = adminCaller(ha, await connect(t, server.url, people.zoner.key, 'modern'));
  const office = { name: 'Office', latitude: -33.86, longitude: 151.2, radius: 250, passive: false, icon: 'mdi:briefcase' };
  const created = await call('ha_write_config', { kind: 'zone', action: 'create', id: 'office', config: office });
  assert.deepEqual(created.sent, [{ type: 'zone/create', ...office }]);
  assert.deepEqual(body(created.result), { kind: 'zone', action: 'create', id: 'office', result: { id: 'office', ...office } });

  const moved = await call('ha_write_config', { kind: 'zone', action: 'update', id: 'office', config: { radius: 100 } });
  assert.deepEqual(moved.sent, [{ type: 'zone/list' }, { type: 'zone/update', ...office, radius: 100, zone_id: 'office' }]);
  assert.deepEqual(ha.zones, [{ id: 'office', ...office, radius: 100 }]);
  const read = await call('ha_get_config', { kind: 'zone', id: 'office' });
  assert.deepEqual(read.sent, [{ type: 'zone/list' }]);
  assert.deepEqual(body(read.result), { config: { id: 'office', ...office, radius: 100 } });
  const marked = await call('ha_write_config', { kind: 'zone', action: 'update', id: 'office', config: { name: M } });
  assert.match(JSON.stringify(marked.result.content), /config carries a redacted value at name/);
  assert.deepEqual(marked.sent, []);

  const deleted = await call('ha_write_config', { kind: 'zone', action: 'delete', id: 'office' });
  assert.deepEqual(deleted.sent, [{ type: 'zone/delete', zone_id: 'office' }]);
  assert.deepEqual(ha.zones, []);
  const gone = await call('ha_get_config', { kind: 'zone', id: 'office' });
  assert.match(JSON.stringify(gone.result.content), /Zone office not found/);

  // A helper Grant writes no zone, and a zone Grant no helper.
  const helperer = adminCaller(ha, await connect(t, server.url, people.helperer.key, 'modern'));
  for (const [who, args] of [
    [helperer, { kind: 'zone', action: 'create', id: 'office', config: office }],
    [helperer, { kind: 'zone', id: 'office' }],
    [call, { kind: 'helper', action: 'create', id: 'input_boolean.guest_mode', config: { name: 'Guest mode' } }],
  ] as const) {
    const denied = await who('action' in args ? 'ha_write_config' : 'ha_get_config', args);
    assert.match(JSON.stringify(denied.result.content), /no Grant for (config writes of zone|zone config|config writes of helper)\. Do not retry/);
    assert.deepEqual(denied.sent, []);
  }
  assert.deepEqual(
    server.audits().map((a) => [a.caller, a.operation, a.kind, a.action, a.decision ?? a.outcome]),
    [
      ['zoner', 'config_write', 'zone', 'create', 'allow'], ['zoner', 'config_write', 'zone', 'create', 'done'],
      ['zoner', 'config_write', 'zone', 'update', 'allow'], ['zoner', 'config_write', 'zone', 'update', 'done'],
      ['zoner', 'config_write', 'zone', 'update', 'deny'],
      ['zoner', 'config_write', 'zone', 'delete', 'allow'], ['zoner', 'config_write', 'zone', 'delete', 'done'],
      ['helperer', 'config_write', 'zone', 'create', 'deny'], ['helperer', 'config_read', 'zone', undefined, 'deny'],
      ['zoner', 'config_write', 'helper', 'create', 'deny'],
    ],
  );
});

const PORCH_BLUEPRINT = 'blueprint:\n  name: Porch at dusk\n  domain: automation\ntriggers:\n  - trigger: sun\n    event: sunset\nactions:\n  - action: light.turn_on\n';

test('an automation writer saves, overwrites and deletes an automation blueprint, audited by domain and path only', async (t) => {
  const { ha, server, as } = await house(t);
  const { call } = await as('automator');
  const save = { type: 'blueprint/save', domain: 'automation', path: 'mine/porch.yaml', yaml: PORCH_BLUEPRINT };
  const created = await call('ha_write_blueprint', { domain: 'automation', action: 'create', path: 'mine/porch', yaml: PORCH_BLUEPRINT });
  assert.deepEqual(created.sent, [save]);
  assert.deepEqual(body(created.result), { domain: 'automation', action: 'create', path: 'mine/porch.yaml', result: { overrides_existing: false } });
  assert.equal((ha.blueprints.automation?.['mine/porch.yaml']?.metadata as { name?: string }).name, 'Porch at dusk');

  const again = await call('ha_write_blueprint', { domain: 'automation', action: 'create', path: 'mine/porch.yaml', yaml: PORCH_BLUEPRINT });
  assert.match(JSON.stringify(again.result.content), /Home Assistant refused the request: File already exists/);
  const updated = await call('ha_write_blueprint', { domain: 'automation', action: 'update', path: 'mine/porch.yaml', yaml: PORCH_BLUEPRINT.replace('Porch at dusk', 'Porch') });
  assert.equal(updated.sent[0]?.allow_override, true);
  assert.deepEqual(body(updated.result), { domain: 'automation', action: 'update', path: 'mine/porch.yaml', result: { overrides_existing: true } });
  const deleted = await call('ha_write_blueprint', { domain: 'automation', action: 'delete', path: 'mine/porch' });
  assert.deepEqual(deleted.sent, [{ type: 'blueprint/delete', domain: 'automation', path: 'mine/porch.yaml' }]);
  assert.equal(ha.blueprints.automation?.['mine/porch.yaml'], undefined);

  assert.deepEqual(
    server.audits().map((a) => [a.tool, a.domain, a.action, a.path, a.decision ?? a.outcome]),
    [
      ['ha_write_blueprint', 'automation', 'create', 'mine/porch.yaml', 'allow'],
      ['ha_write_blueprint', 'automation', 'create', 'mine/porch.yaml', 'done'],
      ['ha_write_blueprint', 'automation', 'create', 'mine/porch.yaml', 'allow'],
      ['ha_write_blueprint', 'automation', 'update', 'mine/porch.yaml', 'allow'],
      ['ha_write_blueprint', 'automation', 'update', 'mine/porch.yaml', 'done'],
      ['ha_write_blueprint', 'automation', 'delete', 'mine/porch.yaml', 'allow'],
      ['ha_write_blueprint', 'automation', 'delete', 'mine/porch.yaml', 'done'],
    ],
  );
  assert.doesNotMatch(JSON.stringify(server.audits()), /Porch|sunset/, 'audit lines carry names, never YAML');
});

test('a blueprint write is refused with nothing sent for the other domain, another kind, a redacted value or a URL to import', async (t) => {
  const { server, as } = await house(t);
  const scriptBlueprint = 'blueprint:\n  name: Ping\n  domain: script\nsequence: []\n';
  const scripter = await as('scripter');
  assert.equal((await scripter.call('ha_write_blueprint', { domain: 'script', action: 'create', path: 'ping', yaml: scriptBlueprint })).result.isError, undefined);
  const crossed = [
    await scripter.call('ha_write_blueprint', { domain: 'automation', action: 'create', path: 'porch', yaml: PORCH_BLUEPRINT }),
    await (await as('automator')).call('ha_write_blueprint', { domain: 'script', action: 'delete', path: 'ping' }),
  ];
  assert.match(JSON.stringify(crossed[0]!.result.content), /no Grant for config writes of automation\. Do not retry/);
  assert.match(JSON.stringify(crossed[1]!.result.content), /no Grant for config writes of script\. Do not retry/);

  // A scene writer holds config writes, but not of a kind blueprints serve, so the tool is hidden and refused.
  const scener = await as('scener');
  assert.equal((await scener.client.listTools()).tools.some((d) => d.name === 'ha_write_blueprint'), false);
  const hidden = await scener.call('ha_write_blueprint', { domain: 'automation', action: 'delete', path: 'porch' });
  assert.match(JSON.stringify(hidden.result.content), /no Grant for config writes of automation or script\. Do not retry/);

  const marked = await scripter.call('ha_write_blueprint', { domain: 'script', action: 'update', path: 'ping', yaml: `${scriptBlueprint}variables:\n  key: ${M}\n` });
  assert.match(JSON.stringify(marked.result.content), /yaml carries a redacted value at line 6: put the real value in its place\. Nothing was sent/);
  const imported = await scripter.call('ha_write_blueprint', { domain: 'script', action: 'create', path: 'ping2', url: 'https://example.com/b.yaml' });
  assert.match(JSON.stringify(imported.result.content), /Input validation error/);
  for (const refused of [...crossed, hidden, marked, imported]) assert.deepEqual(refused.sent, []);

  assert.deepEqual(
    server.audits().filter((a) => a.decision === 'deny').map((a) => [a.caller, a.tool, a.domain, a.action, a.path, a.reason]),
    [
      ['scripter', 'ha_write_blueprint', 'automation', 'create', 'porch.yaml', undefined],
      ['automator', 'ha_write_blueprint', 'script', 'delete', 'ping.yaml', undefined],
      ['scener', 'ha_write_blueprint', undefined, undefined, undefined, undefined],
      ['scripter', 'ha_write_blueprint', 'script', 'update', 'ping.yaml', 'yaml carries a redacted value'],
    ],
  );
  assert.doesNotMatch(JSON.stringify(server.audits()), /Ping|sequence|REDACTED/);
});

test('dashboard writes: create from sidebar settings, update merged over the stored layout, delete by HA\'s collection id; audited by path', async (t) => {
  const { ha, server, as } = await house(t);
  const { call } = await as('dasher');
  const list = { type: 'lovelace/dashboards/list' };
  const sidebar = { title: 'Hall tablet', icon: 'mdi:tablet' };
  const created = await call('ha_write_config', { kind: 'dashboard', action: 'create', id: 'hall-tablet', config: sidebar });
  assert.deepEqual(created.sent, [list, { type: 'lovelace/dashboards/create', url_path: 'hall-tablet', ...sidebar }]);
  const item = { id: 'hall_tablet', url_path: 'hall-tablet', ...sidebar, show_in_sidebar: true, require_admin: false, mode: 'storage' };
  assert.deepEqual(body(created.result), { kind: 'dashboard', action: 'create', id: 'hall-tablet', result: item });
  const taken = await call('ha_write_config', { kind: 'dashboard', action: 'create', id: 'kitchen-wall', config: sidebar });
  assert.match(JSON.stringify(taken.result.content), /The dashboard kitchen-wall already exists/);
  assert.deepEqual(taken.sent, [list]);

  const views = [{ title: 'Hall', cards: [] }];
  const updated = await call('ha_write_config', { kind: 'dashboard', action: 'update', id: 'kitchen-wall', config: { title: 'Wall' } });
  const wall = { ...DASHBOARDS.layouts!['kitchen-wall'], title: 'Wall' };
  assert.deepEqual(updated.sent, [list, { type: 'lovelace/config', url_path: 'kitchen-wall' }, { type: 'lovelace/config/save', url_path: 'kitchen-wall', config: wall }]);
  assert.deepEqual(ha.layouts['kitchen-wall'], wall);
  const home = await call('ha_write_config', { kind: 'dashboard', action: 'update', id: 'lovelace', config: { views } });
  assert.deepEqual(home.sent, [{ type: 'lovelace/config' }, { type: 'lovelace/config/save', config: { title: 'Home', views } }]);
  const unsaved = await call('ha_write_config', { kind: 'dashboard', action: 'update', id: 'spare-room', config: { views } });
  assert.deepEqual(unsaved.sent.at(-1), { type: 'lovelace/config/save', url_path: 'spare-room', config: { views } });
  const missing = await call('ha_write_config', { kind: 'dashboard', action: 'update', id: 'nope', config: { views } });
  assert.match(JSON.stringify(missing.result.content), /The dashboard nope does not exist/);
  assert.deepEqual(missing.sent, [list]);

  const deleted = await call('ha_write_config', { kind: 'dashboard', action: 'delete', id: 'spare-room' });
  assert.deepEqual(deleted.sent, [list, { type: 'lovelace/dashboards/delete', dashboard_id: 'spare_room_2' }]);
  assert.deepEqual(ha.dashboards.map((d) => d.url_path), ['kitchen-wall', 'hall-tablet']);

  for (const [args, refusal] of [
    [{ action: 'create', id: 'lovelace', config: sidebar }, /id: the default dashboard lovelace can only be updated/],
    [{ action: 'delete', id: 'lovelace' }, /id: the default dashboard lovelace can only be updated/],
    [{ action: 'create', id: 'hall', config: { ...sidebar, allow_single_word: true } }, /config: a new dashboard takes only title, icon, show_in_sidebar and require_admin/],
    [{ action: 'update', id: 'kitchen-wall', config: { views: [{ cards: [{ type: 'iframe', url: `https://${M}@cam.local/live` }] }] } }, /config carries a redacted value at views\[0\]\.cards\[0\]\.url/],
  ] as const) {
    const refused = await call('ha_write_config', { kind: 'dashboard', ...args });
    assert.equal(refused.result.isError, true);
    assert.match(JSON.stringify(refused.result.content), refusal);
    assert.deepEqual(refused.sent, []);
  }
  const read = await call('ha_get_config', { kind: 'dashboard', id: 'kitchen-wall' });
  assert.match(JSON.stringify(read.result.content), /kind: a dashboard is read with the dashboard tool/);
  assert.deepEqual(read.sent, []);
  assert.deepEqual(
    server.audits().map((a) => [a.action, a.id, a.decision ?? a.outcome]),
    [
      ['create', 'hall-tablet', 'allow'], ['create', 'hall-tablet', 'done'], ['create', 'kitchen-wall', 'allow'],
      ['update', 'kitchen-wall', 'allow'], ['update', 'kitchen-wall', 'done'], ['update', 'lovelace', 'allow'], ['update', 'lovelace', 'done'],
      ['update', 'spare-room', 'allow'], ['update', 'spare-room', 'done'], ['update', 'nope', 'allow'],
      ['delete', 'spare-room', 'allow'], ['delete', 'spare-room', 'done'], ['update', 'kitchen-wall', 'deny'],
    ],
  );
  assert.doesNotMatch(JSON.stringify(server.audits()), /Hall tablet|views|SECRET/, 'audit lines carry paths, never layouts');
});
