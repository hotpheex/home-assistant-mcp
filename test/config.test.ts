import assert from 'node:assert/strict';
import type { TestContext } from 'node:test';
import { test } from 'node:test';
import { REDACTED as M } from '../src/redaction.ts';
import { ADMIN_TOKEN, body, connect, fakeHa, newKey, startServer } from './harness.ts';

const auditor = newKey();
const writer = newKey();
const policy = `
version: 1
callers:
  auditor:
    keys: [{ sha256: ${auditor.sha256} }]
  writer:
    keys: [{ sha256: ${writer.sha256} }]
grants:
  - caller: auditor
    read: config
  - caller: writer
    config_write: script
`;

async function auditorOn(t: TestContext) {
  const ha = await fakeHa(t);
  const server = await startServer(t, policy, ha, { HAMCP_HA_ADMIN_TOKEN: ADMIN_TOKEN });
  const client = await connect(t, server.url, auditor.key, 'modern');
  const call = async (name: string, args: Record<string, unknown>) => {
    const before = ha.received.length;
    const result = await client.callTool({ name, arguments: args });
    const sent = ha.received.slice(before);
    assert.ok(sent.every((r) => r.token === ADMIN_TOKEN));
    assert.doesNotMatch(JSON.stringify(result), /SECRET/);
    return { result, sent: sent.map((r) => Object.fromEntries(Object.entries(r.message).filter(([k]) => k !== 'id'))) };
  };
  return { ha, server, client, call };
}

test('config read or a config write lists the config-read tools, and nothing else', async (t) => {
  const { server, client } = await auditorOn(t);
  const configTools = ['ha_get_config', 'ha_list_traces', 'ha_get_trace'];
  const names = async (c: typeof client) => (await c.listTools()).tools.map((tool) => tool.name);
  assert.deepEqual(await names(client), configTools);
  const writing = await connect(t, server.url, writer.key, 'modern');
  assert.deepEqual((await names(writing)).filter((name) => configTools.includes(name)), configTools);
});

test('ha_get_config reads an automation or script config with its secrets masked', async (t) => {
  const { call } = await auditorOn(t);
  const automation = await call('ha_get_config', { kind: 'automation', entity_id: 'automation.porch_light' });
  assert.deepEqual(automation.sent, [{ type: 'automation/config', entity_id: 'automation.porch_light' }]);
  assert.deepEqual(body(automation.result), {
    config: {
      id: 'porch_light_1',
      alias: 'Porch light at sunset',
      triggers: [{ trigger: 'sun', event: 'sunset' }],
      actions: [{ action: 'rest_command.notify', data: { api_key: M, url: `https://${M}@nas.local/hook` } }],
    },
  });
  const script = await call('ha_get_config', { kind: 'script', entity_id: 'script.morning' });
  assert.deepEqual(script.sent, [{ type: 'script/config', entity_id: 'script.morning' }]);
  assert.deepEqual(body(script.result), { config: { alias: 'Morning', sequence: [{ action: 'rest_command.ping', data: { header: `Bearer ${M}` } }] } });

  const unknown = await call('ha_get_config', { kind: 'script', entity_id: 'script.nope' });
  assert.equal(unknown.result.isError, true);
  assert.match(JSON.stringify(unknown.result.content), /Entity not found/);
});

test('ha_list_traces requires kind and id, always sends item_id, and pages newest first', async (t) => {
  const { call } = await auditorOn(t);
  const missing = await call('ha_list_traces', { kind: 'automation' });
  assert.equal(missing.result.isError, true);
  assert.deepEqual(missing.sent, []);

  const page = await call('ha_list_traces', { kind: 'automation', id: 'porch_light_1', limit: 2 });
  assert.deepEqual(page.sent, [{ type: 'trace/list', domain: 'automation', item_id: 'porch_light_1' }]);
  const listed = body(page.result) as { total: number; has_more: boolean; traces: Record<string, unknown>[] };
  assert.deepEqual([listed.total, listed.has_more], [3, true]);
  assert.deepEqual(listed.traces.map((s) => s.run_id), ['run_3', 'run_2']);
  assert.deepEqual(Object.keys(listed.traces[0]!).sort(), ['domain', 'item_id', 'last_step', 'run_id', 'script_execution', 'state', 'timestamp', 'trigger']);
});

test('ha_get_trace returns the summary plus the sections asked for, masked and with bearer tokens stripped', async (t) => {
  const { call } = await auditorOn(t);
  const read = await call('ha_get_trace', { kind: 'automation', id: 'porch_light_1', run_id: 'run_2', sections: ['trace', 'context'] });
  assert.deepEqual(read.sent, [{ type: 'trace/get', domain: 'automation', item_id: 'porch_light_1', run_id: 'run_2' }]);
  const trace = body(read.result) as Record<string, unknown>;
  assert.deepEqual(Object.keys(trace).sort(), ['context', 'domain', 'item_id', 'last_step', 'run_id', 'script_execution', 'state', 'timestamp', 'trace', 'trigger']);
  assert.deepEqual(trace.trace, {
    'trigger/0': [
      {
        changed_variables: {
          trigger: { to_state: { entity_id: 'camera.porch', state: 'idle', attributes: { friendly_name: 'Porch', entity_picture: '/api/camera_proxy/camera.porch' } } },
        },
      },
    ],
    'action/0': [{ result: { params: { service_data: { password: M } } } }],
  });

  const config = await call('ha_get_trace', { kind: 'automation', id: 'porch_light_1', run_id: 'run_2', sections: ['config'] });
  assert.deepEqual((body(config.result) as Record<string, unknown>).config, { id: 'porch_light_1', alias: 'Porch light at sunset' });
  const none = await call('ha_get_trace', { kind: 'automation', id: 'porch_light_1', run_id: 'run_2', sections: [] });
  assert.equal(none.result.isError, true);
  const unknown = await call('ha_get_trace', { kind: 'automation', id: 'porch_light_1', run_id: 'run_9', sections: ['trace'] });
  assert.match(JSON.stringify(unknown.result.content), /The trace could not be found/);
});
