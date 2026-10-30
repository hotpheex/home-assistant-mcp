import assert from 'node:assert/strict';
import type { TestContext } from 'node:test';
import { test } from 'node:test';
import type { FakeHaOptions } from './fake-ha.ts';
import { body, connect, ERAS, fakeHa, newKey, policyOf, startServer } from './harness.ts';

const reader = newKey();
const readerPolicy = policyOf({ reader }, 'grants:\n  - caller: reader\n    read: plain\n');

const ago = (minutes: number) => new Date(Date.now() - minutes * 60_000).toISOString();

async function readerOn(t: TestContext, options: Partial<FakeHaOptions> = {}, env: Record<string, string> = {}) {
  const ha = await fakeHa(t, options);
  const server = await startServer(t, readerPolicy, ha, env);
  const client = await connect(t, server.url, reader.key, 'modern');
  const call = async (name: string, args: Record<string, unknown>) => {
    const result = await client.callTool({ name, arguments: args });
    assert.equal(result.isError, undefined, JSON.stringify(result.content));
    return body(result) as Record<string, unknown>;
  };
  const sent = (type: string) => ha.received.filter((r) => r.message.type === type).map((r) => r.message);
  return { ha, server, client, call, sent };
}

/** Asserts an ISO time lies within a few seconds of `minutes` ago. */
const near = (actual: unknown, minutes: number) =>
  assert.ok(Math.abs(Date.parse(String(actual)) - (Date.now() - minutes * 60_000)) < 5000, `${String(actual)} is not ${minutes} min ago`);

test('ha_get_history reads the last 24 h by default, pages rows, and summarises', async (t) => {
  const history = [
    { entity_id: 'sensor.kitchen_temperature', state: '19.0', when: ago(30 * 60) },
    { entity_id: 'sensor.kitchen_temperature', state: '20.5', when: ago(180) },
    { entity_id: 'sensor.kitchen_temperature', state: '22.5', when: ago(120) },
    { entity_id: 'sensor.kitchen_temperature', state: '21.5', when: ago(60) },
    { entity_id: 'light.kitchen', state: 'off', when: ago(300) },
    { entity_id: 'light.kitchen', state: 'on', when: ago(240) },
    { entity_id: 'light.kitchen', state: 'off', when: ago(200) },
    { entity_id: 'light.kitchen', state: 'on', when: ago(30) },
  ];
  const { call, sent } = await readerOn(t, { history });
  const entity_ids = ['sensor.kitchen_temperature', 'light.kitchen'];

  const page = await call('ha_get_history', { entity_ids, limit: 4 });
  const [request] = sent('history/history_during_period');
  assert.deepEqual(request?.entity_ids, entity_ids);
  assert.equal(request?.no_attributes, true);
  near(request?.start_time, 24 * 60);
  near(request?.end_time, 0);
  near(page.start, 24 * 60);
  near(page.end, 0);
  const row = (i: number) => ({ entity_id: history[i]!.entity_id, state: history[i]!.state, last_changed: history[i]!.when });
  assert.deepEqual(
    { total: page.total, offset: page.offset, has_more: page.has_more, history: page.history },
    { total: 7, offset: 0, has_more: true, history: [row(4), row(5), row(6), row(7)] },
  );

  const summary = await call('ha_get_history', { entity_ids, summary: true });
  assert.deepEqual(summary.history, [
    { entity_id: 'light.kitchen', changes: 4, first: 'off', last: 'on', states: { off: 2, on: 2 } },
    { entity_id: 'sensor.kitchen_temperature', changes: 3, first: '20.5', last: '21.5', min: 20.5, max: 22.5, mean: 21.5 },
  ]);

  const window = { start: ago(201), end: ago(100) };
  const narrowed = await call('ha_get_history', { entity_ids, ...window });
  assert.deepEqual(narrowed.history, [row(6), row(1), row(2)]);
  const last = sent('history/history_during_period').at(-1);
  assert.deepEqual([last?.start_time, last?.end_time], [window.start, window.end]);
});

test('ha_get_logbook reads the last hour by default, optionally for one entity', async (t) => {
  const logbook = [
    { when: ago(90), entity_id: 'light.kitchen', name: 'Kitchen Ceiling', state: 'off' },
    { when: ago(40), entity_id: 'light.kitchen', name: 'Kitchen Ceiling', state: 'on' },
    { when: ago(10), entity_id: 'lock.front_door', name: 'Front Door', state: 'locked' },
  ];
  const { call, sent } = await readerOn(t, { logbook });

  const recent = await call('ha_get_logbook', {});
  const [request] = sent('logbook/get_events');
  near(request?.start_time, 60);
  near(request?.end_time, 0);
  assert.equal(request?.entity_ids, undefined);
  assert.deepEqual(
    { total: recent.total, has_more: recent.has_more, entries: recent.entries },
    { total: 2, has_more: false, entries: [logbook[1], logbook[2]] },
  );

  const one = await call('ha_get_logbook', { entity_id: 'lock.front_door', start: ago(120) });
  assert.deepEqual(sent('logbook/get_events').at(-1)?.entity_ids, ['lock.front_door']);
  assert.deepEqual((one.entries as { state: string }[]).map((e) => e.state), ['locked']);
});

test('read: plain lists the five read tools; ha_get_states filters, matches aliases, area and label names, pages, and gives attributes only in full', async (t) => {
  const { call, client } = await readerOn(t);
  const listed = await client.listTools();
  assert.deepEqual(listed.tools.map((tool) => tool.name), ['ha_get_states', 'ha_get_history', 'ha_get_logbook', 'ha_get_registry', 'ha_list_services']);
  assert.equal(listed.cacheScope, 'private');

  const ids = async (args: Record<string, unknown>) => ((await call('ha_get_states', args)).states as { entity_id: string }[]).map((s) => s.entity_id);
  assert.deepEqual(await call('ha_get_states', { domain: 'light' }), {
    total: 2,
    offset: 0,
    has_more: false,
    states: [
      { entity_id: 'light.kitchen', name: 'Kitchen Ceiling', state: 'on' },
      { entity_id: 'light.living_room', name: 'Living Room Lamp', state: 'off' },
    ],
  });
  const page = async (args: Record<string, unknown>) => {
    const { total, offset, has_more } = await call('ha_get_states', args);
    return [total, offset, has_more, await ids(args)];
  };
  assert.deepEqual(await page({ query: 'KITCHEN', limit: 1 }), [2, 0, true, ['light.kitchen']]);
  assert.deepEqual(await page({ query: 'kitchen', limit: 1, offset: 1 }), [2, 1, false, ['sensor.kitchen_temperature']]);
  assert.deepEqual(await ids({ query: 'lamp' }), ['light.living_room']);
  assert.deepEqual(await ids({ query: 'sofa' }), ['light.living_room']);
  assert.deepEqual(await ids({ query: 'UTILITY' }), ['switch.coffee_maker']);
  assert.deepEqual(await ids({ query: 'secur' }), ['lock.front_door']);
  assert.deepEqual(await ids({ state: 'off' }), ['light.living_room', 'switch.coffee_maker']);
  assert.deepEqual((await call('ha_get_states', { domain: 'lock' })).states, [{ entity_id: 'lock.front_door', name: 'Front Door', state: 'locked' }]);
  assert.deepEqual((await call('ha_get_states', { domain: 'lock', full: true })).states, [
    { entity_id: 'lock.front_door', name: 'Front Door', state: 'locked', attributes: { friendly_name: 'Front Door' } },
  ]);
  const tooMany = await client.callTool({ name: 'ha_get_states', arguments: { limit: 501 } });
  assert.equal(tooMany.isError, true);
  assert.match(JSON.stringify(tooMany.content), /limit/);
});

test('every read strips camera, image and media_player bearer tokens', async (t) => {
  const { client } = await readerOn(t);
  const result = await client.callTool({ name: 'ha_get_states', arguments: { full: true } });
  assert.doesNotMatch(JSON.stringify(result), /SECRET/);
  const states = (body(result) as { states: { entity_id: string; attributes: Record<string, unknown> }[] }).states;
  const attributes = (id: string) => states.find((s) => s.entity_id === id)?.attributes;
  assert.deepEqual(attributes('camera.porch'), { friendly_name: 'Porch', entity_picture: '/api/camera_proxy/camera.porch' });
  assert.deepEqual(attributes('media_player.den'), { friendly_name: 'Den Speaker', entity_picture: '/api/media_player_proxy/media_player.den?cache=42' });
});

test('a read over the character cap is refused with "narrow the query", never cut off; one at the cap is returned whole', async (t) => {
  // Claude Code saves a text result over 50,000 characters to a file, so the cap sits just below it.
  const cap = 48_000;
  const states = [{ entity_id: 'sensor.bulk', state: '1', attributes: { friendly_name: 'Bulk', note: '' } }];
  const { client } = await readerOn(t, { states });
  const textLength = async () => ((await client.callTool({ name: 'ha_get_states', arguments: { full: true } })).content as { text: string }[])[0]!.text.length;
  const padding = cap - (await textLength());

  states[0]!.attributes.note = 'x'.repeat(padding);
  assert.equal(await textLength(), cap);

  // One character over, and still well under 80 kB in bytes.
  states[0]!.attributes.note = 'x'.repeat(padding + 1);
  const refused = await client.callTool({ name: 'ha_get_states', arguments: { full: true } });
  assert.equal(refused.isError, true);
  const message = (refused.content as { text: string }[])[0]!.text;
  assert.match(message, /narrow the query/);
  assert.match(message, /48000 characters/);
  assert.doesNotMatch(message, /window/);
});

test("history's size refusal offers a shorter window", async (t) => {
  const history = Array.from({ length: 300 }, (_, i) => ({ entity_id: 'sensor.bulk', state: String(i).padEnd(200, 'x'), when: ago(300 - i) }));
  const { client } = await readerOn(t, { history });
  const refused = await client.callTool({ name: 'ha_get_history', arguments: { entity_ids: ['sensor.bulk'], limit: 300 } });
  assert.equal(refused.isError, true);
  assert.match((refused.content as { text: string }[])[0]!.text, /narrow the query with .*a shorter window/);
});

for (const era of ERAS) {
  test(`server instructions follow the visible tools, never the Grants (${era})`, async (t) => {
    const [twin, idle] = [newKey(), newKey()];
    const ha = await fakeHa(t);
    // twin sees the same tools as reader through a different Policy; idle sees none.
    const policy = policyOf(
      { reader, twin, idle },
      `grants:
  - caller: reader
    read: plain
  - caller: twin
    read: plain
denies:
  - caller: twin
    services: [lock.unlock]
`,
    );
    const server = await startServer(t, policy, ha);
    const instructions = async (key: string) => (await connect(t, server.url, key, era)).getInstructions() ?? '';
    const forReader = await instructions(reader.key);
    assert.match(forReader, /ha_get_states/);
    assert.match(forReader, /has_more/);
    assert.ok(forReader.length < 4096);
    assert.equal(await instructions(twin.key), forReader);
    assert.doesNotMatch(await instructions(idle.key), /ha_get_states/);
  });
}

test('allowed reads are audited, naming the read kind and request, only with HAMCP_AUDIT_READS', async (t) => {
  const { call, server } = await readerOn(t, {}, { HAMCP_AUDIT_READS: 'true' });
  await call('ha_get_registry', { registry: 'area', query: 'utility' });
  const [record, ...rest] = server.audits();
  assert.deepEqual(rest, []);
  assert.deepEqual(
    { ...record, time: undefined },
    {
      time: undefined,
      audit: true,
      caller: 'reader',
      key_hash_prefix: reader.sha256.slice(0, 8),
      operation: 'plain_read',
      tool: 'ha_get_registry',
      decision: 'allow',
      grants: [0],
      request: { registry: 'area', query: 'utility', limit: 50, offset: 0 },
    },
  );
});

test('ha_get_registry lists each registry, filtered by a query', async (t) => {
  const { call, sent } = await readerOn(t);
  const ids = { entity: 'entity_id', device: 'id', area: 'area_id', label: 'label_id', floor: 'floor_id' } as const;
  const expected = {
    entity: ['switch.coffee_maker', 'light.living_room', 'lock.front_door'],
    device: ['dev_coffee'],
    area: ['utility_room'],
    label: ['security'],
    floor: ['ground'],
  };
  for (const [registry, key] of Object.entries(ids) as [keyof typeof ids, string][]) {
    const listed = await call('ha_get_registry', { registry });
    assert.equal(sent(`config/${registry}_registry/list`).length, 1);
    assert.deepEqual((listed.entries as Record<string, unknown>[]).map((e) => e[key]), expected[registry], registry);
  }
  const found = await call('ha_get_registry', { registry: 'entity', query: 'COFFEE', limit: 1 });
  assert.deepEqual([found.total, found.has_more], [1, false]);
  assert.deepEqual((await call('ha_get_registry', { registry: 'area', query: 'utility' })).entries, [
    { area_id: 'utility_room', name: 'Utility Room', floor_id: 'ground', aliases: [] },
  ]);
  assert.equal((await call('ha_get_registry', { registry: 'entity', limit: 2 })).has_more, true);
});
