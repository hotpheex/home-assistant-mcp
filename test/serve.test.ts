import assert from 'node:assert/strict';
import { test } from 'node:test';
import { OPERATION_TIER, type Operation } from '../src/evaluator.ts';
import { TOOL_KIND, type ToolName } from '../src/tools.ts';
import { ADMIN_TOKEN, body, connect, ERAS, fakeHa, newKey, startServer, USERS_TOKEN } from './harness.ts';

const reader = newKey();
const readerPolicy = `
version: 1
callers:
  reader:
    keys:
      - sha256: ${reader.sha256}
grants:
  - caller: reader
    read: plain
`;

for (const era of ERAS) {
  test(`a Caller with read: plain lists states, filtered and paged (${era})`, async (t) => {
    const ha = await fakeHa(t);
    const server = await startServer(t, readerPolicy, ha);
    const client = await connect(t, server.url, reader.key, era);

    const listed = await client.listTools();
    assert.deepEqual(
      listed.tools.map((tool) => tool.name),
      ['ha_get_states'],
    );
    if (era === 'modern') assert.equal(listed.cacheScope, 'private');

    const call = async (args: Record<string, unknown>) => {
      const result = await client.callTool({ name: 'ha_get_states', arguments: args });
      assert.equal(result.isError, undefined);
      return body(result);
    };
    assert.deepEqual(await call({ domain: 'light' }), {
      total: 2,
      offset: 0,
      has_more: false,
      states: [
        { entity_id: 'light.kitchen', name: 'Kitchen Ceiling', state: 'on' },
        { entity_id: 'light.living_room', name: 'Living Room Lamp', state: 'off' },
      ],
    });
    assert.deepEqual(await call({ query: 'KITCHEN', limit: 1 }), {
      total: 2,
      offset: 0,
      has_more: true,
      states: [{ entity_id: 'light.kitchen', name: 'Kitchen Ceiling', state: 'on' }],
    });
    assert.deepEqual(await call({ query: 'kitchen', limit: 1, offset: 1 }), {
      total: 2,
      offset: 1,
      has_more: false,
      states: [{ entity_id: 'sensor.kitchen_temperature', name: 'Kitchen Temperature', state: '21.5' }],
    });
    assert.deepEqual(await call({ query: 'lamp' }), {
      total: 1,
      offset: 0,
      has_more: false,
      states: [{ entity_id: 'light.living_room', name: 'Living Room Lamp', state: 'off' }],
    });

    const tooMany = await client.callTool({ name: 'ha_get_states', arguments: { limit: 501 } });
    assert.equal(tooMany.isError, true);
    assert.match(JSON.stringify(tooMany.content), /limit/);
  });
}

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

test('a request with an Origin outside HAMCP_ALLOWED_ORIGINS gets 403', async (t) => {
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
});

/** A Grant that gives each Operation, for the matrix rows that hold it. */
const GRANT_FOR: Record<Operation, string> = {
  plain_read: 'read: plain',
  config_read: 'read: config',
  service_call: 'services: [light.turn_on]\n    targets: [{ domain: light }]',
  config_write: 'config_write: automation',
};
const SAMPLE_ARGS: Record<ToolName, Record<string, unknown>> = {
  ha_get_states: {},
  ha_call_service: { domain: 'light', service: 'turn_on', target: { entity_id: 'light.kitchen' } },
};
const TIER_TOKEN = { users: USERS_TOKEN, admin: ADMIN_TOKEN };

// The coverage matrix: every tool, from the code's own maps, against holding or lacking its kind.
for (const era of ERAS) {
  for (const [tool, kind] of Object.entries(TOOL_KIND) as [ToolName, Operation][]) {
    test(`matrix: ${tool} for a Caller holding or lacking ${kind} (${era})`, async (t) => {
      const holder = newKey();
      const idle = newKey();
      const ha = await fakeHa(t);
      const server = await startServer(
        t,
        `
version: 1
callers:
  holder:
    keys: [{ sha256: ${holder.sha256} }]
  idle:
    keys: [{ sha256: ${idle.sha256} }]
grants:
  - caller: holder
    ${GRANT_FOR[kind]}
`,
        ha,
        { HAMCP_HA_ADMIN_TOKEN: ADMIN_TOKEN },
      );

      const holding = await connect(t, server.url, holder.key, era);
      assert.ok((await holding.listTools()).tools.some((d) => d.name === tool));
      const before = ha.received.length;
      const allowed = await holding.callTool({ name: tool, arguments: SAMPLE_ARGS[tool] });
      assert.equal(allowed.isError, undefined);
      const sent = ha.received.slice(before);
      assert.ok(sent.length > 0);
      assert.deepEqual(new Set(sent.map((r) => r.token)), new Set([TIER_TOKEN[OPERATION_TIER[kind]]]));

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
