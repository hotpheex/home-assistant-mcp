import assert from 'node:assert/strict';
import type { TestContext } from 'node:test';
import { test } from 'node:test';
import { REDACTED as M } from '../src/redaction.ts';
import { ADMIN_TOKEN, adminCaller, body, connect, fakeHa, newKey, policyOf, startServer, until } from './harness.ts';

const keys = Object.fromEntries(['auditor', 'automator', 'scripter', 'scener', 'helperer'].map((name) => [name, newKey()]));
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
  assert.deepEqual(auditing.map((d) => d.name), ['ha_get_config', 'ha_list_traces', 'ha_get_trace']);
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

  const [audit] = server.audits().filter((a) => a.caller === 'automator');
  assert.deepEqual(
    { ...audit, time: undefined },
    {
      time: undefined,
      audit: true,
      caller: 'automator',
      key_hash_prefix: keys.automator!.sha256.slice(0, 8),
      operation: 'config_write',
      tool: 'ha_write_config',
      kind: 'automation',
      action: 'create',
      id: 'hall_light',
      decision: 'allow',
      grants: [1],
    },
  );
});

test('an update merges its top-level keys into the stored config, since HA replaces the whole entry', async (t) => {
  const { ha, as } = await house(t);
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
});

test('deletes, and script and scene writes, go to their own config endpoints', async (t) => {
  const { ha, as } = await house(t);
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

test('helper writes go through the helper domain WebSocket commands, which merge updates themselves', async (t) => {
  const { ha, as } = await house(t);
  const { call } = await as('helperer');
  const created = await call('ha_write_config', { kind: 'helper', action: 'create', id: 'input_boolean.guest_mode', config: { name: 'Guest mode' } });
  assert.deepEqual(created.sent, [{ type: 'input_boolean/create', name: 'Guest mode' }]);
  assert.deepEqual(body(created.result), { kind: 'helper', action: 'create', id: 'input_boolean.guest_mode', result: { id: 'guest_mode', name: 'Guest mode' } });

  const updated = await call('ha_write_config', { kind: 'helper', action: 'update', id: 'input_text.wifi_password', config: { initial: 'y' } });
  assert.deepEqual(updated.sent, [{ type: 'input_text/update', initial: 'y', input_text_id: 'wifi_password' }]);
  assert.deepEqual(ha.helpers.input_text, [{ id: 'wifi_password', name: 'Wifi password', initial: 'y', api_key: 'HELPERSECRET' }]);

  const deleted = await call('ha_write_config', { kind: 'helper', action: 'delete', id: 'input_boolean.guest_mode' });
  assert.deepEqual(deleted.sent, [{ type: 'input_boolean/delete', input_boolean_id: 'guest_mode' }]);
  const unknown = await call('ha_write_config', { kind: 'helper', action: 'update', id: 'timer.nope', config: { duration: '00:01:00' } });
  assert.match(JSON.stringify(unknown.result.content), /Home Assistant refused the request: Unable to find timer_id nope/);

  const person = await call('ha_write_config', { kind: 'helper', action: 'delete', id: 'person.bob' });
  assert.match(JSON.stringify(person.result.content), /id: must be <helper domain>\.<id>/);
  assert.deepEqual(person.sent, []);
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
  const helper = await helperer.call('ha_get_config', { kind: 'helper', id: 'input_text.wifi_password' });
  assert.deepEqual(helper.sent, [{ type: 'input_text/list' }]);
  assert.deepEqual(body(helper.result), { config: { id: 'wifi_password', name: 'Wifi password', initial: 'x', api_key: M } });
  const automation = await helperer.call('ha_get_config', { kind: 'automation', entity_id: 'automation.porch_light' });
  assert.equal(automation.result.isError, undefined, 'any config write gives automation and script config read');
  const noId = await helperer.call('ha_get_config', { kind: 'helper', entity_id: 'input_text.wifi_password' });
  assert.match(JSON.stringify(noId.result.content), /id: is required for a helper/);

  for (const [who, args] of [
    ['auditor', { kind: 'scene', id: 'movie_night_1' }],
    ['auditor', { kind: 'helper', id: 'input_text.wifi_password' }],
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
