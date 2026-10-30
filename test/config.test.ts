import assert from 'node:assert/strict';
import type { TestContext } from 'node:test';
import { test } from 'node:test';
import { REDACTED as M } from '../src/redaction.ts';
import { ADMIN_TOKEN, adminCaller, body, connect, fakeHa, newKey, policyOf, REGISTRIES, startServer } from './harness.ts';

const ID_HINT = "Name it by an automation's config id or a script's object id (the part after script.), not by its entity_id.";
const auditor = newKey();
const policy = policyOf({ auditor }, 'grants:\n  - caller: auditor\n    read: config\n');

/** The registry entries that tell trace calls their item exists; yaml_porch_1 is an automation from YAML with no runs. */
const ITEMS = [
  { entity_id: 'automation.porch_light', platform: 'automation', unique_id: 'porch_light_1' },
  { entity_id: 'automation.yaml_porch', platform: 'automation', unique_id: 'yaml_porch_1' },
  { entity_id: 'script.morning', platform: 'script', unique_id: 'morning' },
];

async function auditorOn(t: TestContext) {
  const ha = await fakeHa(t, { entities: [...REGISTRIES.entities!, ...ITEMS] });
  const server = await startServer(t, policy, ha, { HAMCP_HA_ADMIN_TOKEN: ADMIN_TOKEN });
  const client = await connect(t, server.url, auditor.key, 'modern');
  return { ha, server, client, call: adminCaller(ha, client) };
}

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

  const mismatch = await call('ha_get_config', { kind: 'automation', entity_id: 'script.morning' });
  assert.match(JSON.stringify(mismatch.result.content), /entity_id: its domain must match kind: an automation takes automation\.<id>/);
  assert.deepEqual(mismatch.sent, []);
  const extraId = await call('ha_get_config', { kind: 'automation', entity_id: 'automation.porch_light', id: 'porch_light_1' });
  assert.match(JSON.stringify(extraId.result.content), /id: is not taken for an automation, which takes only entity_id/);
  assert.deepEqual(extraId.sent, []);
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

  assert.deepEqual(body((await call('ha_list_traces', { kind: 'automation', id: 'yaml_porch_1' })).result), { total: 0, offset: 0, has_more: false, traces: [] });
  // A typo, an entity_id or the wrong kind names nothing.
  for (const [kind, id] of [['automation', 'porch_light_9'], ['automation', 'automation.porch_light'], ['script', 'porch_light_1']]) {
    const wrong = await call('ha_list_traces', { kind, id });
    assert.equal(wrong.result.isError, true);
    assert.deepEqual(wrong.result.content, [{ type: 'text', text: `No ${kind} has the id ${id}. ${ID_HINT}` }]);
  }
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
  const wrong = await call('ha_get_trace', { kind: 'automation', id: 'automation.porch_light', run_id: 'run_2', sections: ['trace'] });
  assert.equal(wrong.result.isError, true);
  assert.deepEqual(wrong.result.content, [{ type: 'text', text: `No automation has the id automation.porch_light. ${ID_HINT}` }]);
});
