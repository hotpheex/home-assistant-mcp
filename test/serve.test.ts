import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decideRead, decideServiceCall, NAME_LOOKUP, planServiceCall, type Allowed, type ConfigKind, type Operation } from '../src/evaluator.ts';
import { openGate } from '../src/gate.ts';
import { parsePolicy } from '../src/policy.ts';
import { TOOL_KIND, type ToolName } from '../src/tools.ts';
import { ADMIN_TOKEN, connect, ERAS, fakeHa, newKey, policyOf, startServer, STARTUP_COMMANDS, USERS_TOKEN } from './harness.ts';
import type { FakeHaOptions } from './fake-ha.ts';

const reader = newKey();
const readerPolicy = policyOf({ reader }, 'grants:\n  - caller: reader\n    read: plain\n');

test('missing, malformed, unknown and expired keys get the same 401, each audited without the key', async (t) => {
  const expired = newKey();
  const unknown = newKey();
  const ha = await fakeHa(t);
  const server = await startServer(
    t,
    `
version: 1
callers:
  reader:
    keys: [{ sha256: ${reader.sha256} }]
  lapsed:
    keys: [{ sha256: ${expired.sha256}, expires: 2020-01-01 }]
grants:
  - caller: reader
    read: plain
  - caller: lapsed
    read: plain
`,
    ha,
  );
  const cases = [
    { reason: 'missing', headers: {} },
    { reason: 'malformed', headers: { authorization: `Bearer ${reader.key}x` } },
    { reason: 'malformed', headers: { authorization: `Basic ${reader.key}` } },
    { reason: 'unknown', headers: { authorization: `Bearer ${unknown.key}` } },
    { reason: 'expired', headers: { authorization: `Bearer ${expired.key}` } },
  ];
  for (const { headers } of cases) {
    const res = await fetch(server.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
    assert.equal(res.status, 401);
    assert.equal(res.headers.get('www-authenticate'), 'Bearer');
    assert.equal(await res.text(), '');
  }

  const audits = server.audits();
  assert.deepEqual(
    audits.map((a) => [a.operation, a.decision, a.reason, a.remote]),
    cases.map((c) => ['authenticate', 'deny', c.reason, '127.0.0.1']),
  );
  assert.equal(audits[4]?.caller, 'lapsed');
  assert.equal(audits[4]?.key_hash_prefix, expired.sha256.slice(0, 8));
  assert.doesNotMatch(server.lines.join('\n'), /hamcp_/);
});

test('a request with an Origin outside HAMCP_ALLOWED_ORIGINS gets 403 and is audited', async (t) => {
  const ha = await fakeHa(t);
  const server = await startServer(t, readerPolicy, ha, { HAMCP_ALLOWED_ORIGINS: 'https://allowed.example' });
  const post = (origin: string) =>
    fetch(server.url, {
      method: 'POST',
      headers: { origin, authorization: `Bearer ${reader.key}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    });
  assert.equal((await post('https://evil.example')).status, 403);
  assert.equal((await post('https://allowed.example')).status, 200);
  assert.deepEqual(
    server.records().filter((r) => r.audit).map((r) => [r.decision, r.reason, r.origin]),
    [['deny', 'origin not allowed', 'https://evil.example']],
  );
});

/** A Grant that gives each Operation, for the matrix rows that hold it. */
const GRANT_FOR: Record<Operation, string> = {
  plain_read: 'read: plain',
  config_read: 'read: config',
  service_call: 'services: [light.turn_on]\n    targets: [{ domain: light }]',
  config_write: 'config_write: automation',
};
/** A holder Grant for a tool whose sample call needs more than its Operation's Grant. */
const HOLDER_GRANT: Partial<Record<ToolName, string>> = {
  ha_helper_flow: 'config_write: helper_entry',
};
const SAMPLE_ARGS: Record<ToolName, Record<string, unknown>> = {
  ha_get_states: { query: 'kitchen', area: 'utility_room' },
  ha_get_history: { entity_ids: ['light.kitchen'] },
  ha_get_logbook: {},
  ha_get_registry: { registry: 'entity' },
  ha_get_config: { kind: 'automation', entity_id: 'automation.porch_light' },
  ha_list_traces: { kind: 'automation', id: 'porch_light_1' },
  ha_get_trace: { kind: 'automation', id: 'porch_light_1', run_id: 'run_1', sections: ['trace'] },
  ha_write_config: { kind: 'automation', action: 'update', id: 'porch_light_1', config: { alias: 'Porch light at dusk' } },
  ha_list_services: {},
  ha_call_service: { domain: 'light', service: 'turn_on', target: { entity_id: 'light.kitchen' } },
  ha_get_statistics: { statistic_ids: ['sensor.kitchen_temperature'] },
  ha_render_template: { template: "{{ states('light.kitchen') }}" },
  ha_get_logs: {},
  ha_list_blueprints: { domain: 'automation' },
  ha_write_blueprint: { domain: 'automation', action: 'create', path: 'mine/dusk', yaml: 'blueprint:\n  name: Dusk\n  domain: automation\n' },
  ha_helper_flow: { action: 'start', handler: 'template' },
};
/** The read-only commands a read tool may send, written out here rather than taken from the gate. */
const PURE_READS = new Set([
  'get_states',
  'get_services',
  'extract_from_target',
  'config/entity_registry/list',
  'config/entity_registry/get_entries',
  'config/device_registry/list',
  'config/area_registry/list',
  'config/label_registry/list',
  'config/floor_registry/list',
  'history/history_during_period',
  'logbook/get_events',
  'automation/config',
  'script/config',
  'trace/list',
  'trace/get',
  'render_template',
  'unsubscribe_events',
  ...['input_boolean', 'input_number', 'input_select', 'input_text', 'input_datetime', 'input_button', 'counter', 'timer', 'schedule'].map((d) => `${d}/list`),
  'recorder/list_statistic_ids',
  'recorder/statistics_during_period',
  'system_log/list',
  'blueprint/list',
]);
test('the gate sends only an Allowed the evaluator issued, as issued: a forged, spread or altered one sends nothing', async (t) => {
  const ha = await fakeHa(t);
  const gate = openGate(ha.url, new Map([['users', USERS_TOKEN], ['admin', ADMIN_TOKEN]] as const), () => {}, (reason) => assert.fail(reason));
  t.after(() => gate.close());
  await gate.connected;
  const before = ha.received.length;
  const unlock = { type: 'call_service', domain: 'lock', service: 'unlock', target: { entity_id: ['lock.front_door'] }, service_data: {} };
  const post = { method: 'POST', path: '/api/config/automation/config/x', body: {} } as const;
  const forged: Allowed[] = [
    { ...NAME_LOOKUP, operation: 'service_call', write: { via: 'websocket', command: unlock } },
    { ...NAME_LOOKUP, operation: 'config_write', tier: 'admin', write: { via: 'rest', request: post } },
  ];
  await assert.rejects(gate.send(forged[0]!, unlock), /evaluator issued/);
  await assert.rejects(gate.rest(forged[1]!, post), /evaluator issued/);
  await assert.rejects(gate.subscribeOnce(forged[0]!, { type: 'render_template', template: '{{ 1 }}' }), /evaluator issued/);
  assert.throws(() => Object.assign(NAME_LOOKUP, { operation: 'service_call', write: { via: 'websocket', command: unlock } }), TypeError);
  await assert.rejects(gate.send(NAME_LOOKUP, unlock), /may not send call_service/);
  // Only a template render may subscribe, and it may not go as a plain send, which would leave its subscription open.
  const render = { type: 'render_template', template: '{{ 1 }}' };
  await assert.rejects(gate.subscribeOnce(NAME_LOOKUP, { type: 'subscribe_events', event_type: 'state_changed' }), /may not subscribe to subscribe_events/);
  await assert.rejects(gate.subscribeOnce(decideRead(parsePolicy('version: 1\ncallers: { agent: { keys: [] } }\ngrants:\n  - caller: agent\n    read: config\n'), 'agent', 'config_read').allowed!, render), /config_read may not subscribe/);
  await assert.rejects(gate.send(NAME_LOOKUP, render), /may not send render_template/);
  assert.equal(await gate.subscribeOnce(NAME_LOOKUP, render).then((e) => (e as { result: unknown }).result), '{{ 1 }}');

  const policy = parsePolicy(`version: 1\ncallers: { agent: { keys: [] } }\ngrants:\n  - caller: agent\n    services: [light.turn_on]\n    targets: [{ domain: light }]\n`);
  const expansion = { targeted: true, entities: ['light.kitchen'], grantEntities: [], denyEntities: [] };
  const plan = planServiceCall(policy, 'agent', 'light.turn_on').plan!;
  const { allowed } = decideServiceCall(policy, plan, expansion, { domain: 'light', service: 'turn_on', data: {}, responds: false });
  const { target } = allowed!.write.command as unknown as { target: { entity_id: string[] } };
  assert.throws(() => target.entity_id.push('lock.front_door'), TypeError);
  const writes = () => ha.received.slice(before).filter((r) => r.message.type === 'call_service' || r.message.type.startsWith('POST '));
  assert.deepEqual(writes(), []);
  await gate.send(allowed!, allowed!.write.command);
  assert.deepEqual(writes().map((r) => r.message.target), [{ entity_id: ['light.kitchen'] }]);
});

// The coverage matrix: every tool, from the code's own maps, against holding or lacking its kind.
for (const era of ERAS) {
  for (const [tool, kind] of Object.entries(TOOL_KIND) as [ToolName, Operation][]) {
    test(`matrix: ${tool} for a Caller holding or lacking ${kind} (${era})`, async (t) => {
      const holder = newKey();
      const idle = newKey();
      const ha = await fakeHa(t);
      const server = await startServer(t, policyOf({ holder, idle }, `grants:\n  - caller: holder\n    ${HOLDER_GRANT[tool] ?? GRANT_FOR[kind]}\n`), ha, { HAMCP_HA_ADMIN_TOKEN: ADMIN_TOKEN });

      const holding = await connect(t, server.url, holder.key, era);
      const definition = (await holding.listTools()).tools.find((d) => d.name === tool);
      assert.ok(definition?.title);
      assert.equal(typeof definition.annotations?.destructiveHint, 'boolean');
      assert.equal(definition.annotations?.readOnlyHint, kind === 'plain_read' || kind === 'config_read');
      const sentences = definition.description?.match(/[.!?](?=\s|$)/g)?.length ?? 0;
      assert.ok(sentences >= 3 && sentences <= 6, `${tool} has ${sentences} sentences`);
      assert.doesNotMatch(definition.description ?? '', /\bha_/, 'a description points to no other tool');
      assert.deepEqual(ha.received.map((r) => r.message.type).filter((type) => !STARTUP_COMMANDS.includes(type)), []);
      const before = ha.received.length;
      const allowed = await holding.callTool({ name: tool, arguments: SAMPLE_ARGS[tool] });
      assert.equal(allowed.isError, undefined);
      const sent = ha.received.slice(before);
      assert.ok(sent.length > 0);
      // The admin pin, written out here rather than read from the code it pins.
      assert.deepEqual(new Set(sent.map((r) => r.token)), new Set([kind.startsWith('config_') ? ADMIN_TOKEN : USERS_TOKEN]));
      if (definition.annotations?.readOnlyHint) {
        assert.deepEqual(sent.map((r) => r.message.type).filter((type) => !PURE_READS.has(type)), [], 'a read tool sends only read-only commands');
      }

      const lacking = await connect(t, server.url, idle.key, era);
      assert.deepEqual((await lacking.listTools()).tools, []);
      const quiet = ha.received.length;
      // Refused before its input is read: valid and invalid arguments get the same denial.
      for (const args of [SAMPLE_ARGS[tool], { not_an_input: true }]) {
        const denied = await lacking.callTool({ name: tool, arguments: args });
        assert.equal(denied.isError, true);
        assert.match(JSON.stringify(denied.content), /Do not retry/);
      }
      assert.equal(ha.received.length, quiet);
      assert.deepEqual(server.audits().filter((a) => a.caller === 'holder'), [], 'allowed calls are audited only on opt-in');
      const audits = server.audits().filter((a) => a.caller === 'idle');
      assert.equal(audits.length, 2);
      for (const a of audits) {
        assert.equal(a.decision, 'deny');
        assert.equal(a.operation, kind);
        assert.equal(a.tool, tool);
        assert.equal(a.key_hash_prefix, idle.sha256.slice(0, 8));
      }
    });
  }
}

/** A config-write kind that only its own Grant gives, with a seeded house and a sample config read and update of it. */
const KIND_SAMPLES: Partial<Record<ConfigKind, { seed: Partial<FakeHaOptions>; read: Record<string, unknown>; write: Record<string, unknown> }>> = {
  zone: {
    seed: { zones: [{ id: 'office', name: 'Office', latitude: -33.86, longitude: 151.2, radius: 250, passive: false }] },
    read: { kind: 'zone', id: 'office' },
    write: { kind: 'zone', action: 'update', id: 'office', config: { radius: 100 } },
  },
};
for (const [kind, sample] of Object.entries(KIND_SAMPLES) as [ConfigKind, NonNullable<(typeof KIND_SAMPLES)[ConfigKind]>][]) {
  test(`matrix: ${kind} config read and write for a Caller holding or lacking config_write: ${kind}`, async (t) => {
    const holder = newKey();
    const other = newKey();
    const ha = await fakeHa(t, sample.seed);
    const grants = `grants:\n  - caller: holder\n    config_write: ${kind}\n  - caller: other\n    config_write: automation\n`;
    const server = await startServer(t, policyOf({ holder, other }, grants), ha, { HAMCP_HA_ADMIN_TOKEN: ADMIN_TOKEN });
    const calls = [['ha_get_config', sample.read, 'config_read'], ['ha_write_config', sample.write, 'config_write']] as const;
    const holding = await connect(t, server.url, holder.key, 'modern');
    for (const [tool, args] of calls) {
      const before = ha.received.length;
      assert.equal((await holding.callTool({ name: tool, arguments: args })).isError, undefined);
      assert.deepEqual(new Set(ha.received.slice(before).map((r) => r.token)), new Set([ADMIN_TOKEN]));
    }
    const lacking = await connect(t, server.url, other.key, 'modern');
    const quiet = ha.received.length;
    for (const [tool, args] of calls) assert.match(JSON.stringify((await lacking.callTool({ name: tool, arguments: args })).content), /Do not retry/);
    assert.equal(ha.received.length, quiet);
    assert.deepEqual(
      server.audits().map((a) => [a.caller, a.operation, a.tool, a.kind, a.decision]),
      calls.map(([tool, , operation]) => ['other', operation, tool, kind, 'deny']),
    );
  });
}
