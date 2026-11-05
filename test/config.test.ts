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
  assert.match(JSON.stringify((await call('ha_get_config', { kind: 'script' })).result.content), /entity_id: is required for a script/);
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

/** HA's system log, oldest first as recorded; HA lists it newest first. */
const SYSTEM_LOG = [
  { name: 'homeassistant.components.hue', level: 'WARNING', message: ['Bridge slow to answer'], source: ['components/hue/bridge.py', 80], timestamp: 1_793_000_000, exception: '', count: 1, first_occurred: 1_793_000_000 },
  {
    name: 'homeassistant.components.automation.porch_light',
    level: 'ERROR',
    message: ['Error in action: https://bob:LOGSECRET@nas.local/hook refused Bearer LOGSECRET1'],
    source: ['components/automation/__init__.py', 712],
    timestamp: 1_793_000_120.5,
    exception: '',
    count: 2,
    first_occurred: 1_793_000_060,
  },
  { name: 'custom_components.nas', level: 'INFO', message: ['Polled the NAS'], source: ['custom_components/nas/sensor.py', 33], timestamp: 1_793_000_180, exception: '', count: 1, first_occurred: 1_793_000_180 },
];

test('ha_get_logs lists the system log newest first, filtered by minimum level and query, with secrets masked', async (t) => {
  const ha = await fakeHa(t, { systemLog: SYSTEM_LOG });
  const server = await startServer(t, policy, ha, { HAMCP_HA_ADMIN_TOKEN: ADMIN_TOKEN });
  const call = adminCaller(ha, await connect(t, server.url, auditor.key, 'modern'));
  const names = async (args: Record<string, unknown>) => {
    const { result, sent } = await call('ha_get_logs', args);
    assert.deepEqual(sent, [{ type: 'system_log/list' }]);
    return (body(result) as { entries: { name: string }[] }).entries.map((e) => e.name);
  };
  assert.deepEqual(await names({}), ['custom_components.nas', 'homeassistant.components.automation.porch_light', 'homeassistant.components.hue']);
  assert.deepEqual(await names({ level: 'warning' }), ['homeassistant.components.automation.porch_light', 'homeassistant.components.hue']);
  assert.deepEqual(await names({ level: 'critical' }), []);
  // The query matches the logger name, the source path or a message, case-insensitively.
  assert.deepEqual(await names({ query: 'HUE' }), ['homeassistant.components.hue']);
  assert.deepEqual(await names({ query: 'nas/sensor.py' }), ['custom_components.nas']);
  assert.deepEqual(await names({ query: 'error in action', level: 'error' }), ['homeassistant.components.automation.porch_light']);
  // It matches the masked text, so a query cannot probe for a secret.
  assert.deepEqual(await names({ query: 'LOGSECRET' }), []);

  const page = body((await call('ha_get_logs', { level: 'error' })).result);
  assert.deepEqual(page, {
    total: 1,
    offset: 0,
    has_more: false,
    entries: [
      {
        name: 'homeassistant.components.automation.porch_light',
        level: 'ERROR',
        message: [`Error in action: https://${M}@nas.local/hook refused Bearer ${M}`],
        source: ['components/automation/__init__.py', 712],
        timestamp: '2026-10-26T07:35:20.500Z',
        exception: '',
        count: 2,
        first_occurred: '2026-10-26T07:34:20.000Z',
      },
    ],
  });
  assert.equal((await call('ha_get_logs', { level: 'fatal' })).result.isError, true);
});

test('ha_list_blueprints lists automation and script blueprints by path, with their metadata masked', async (t) => {
  const { call } = await auditorOn(t);
  const both = await call('ha_list_blueprints', {});
  assert.deepEqual(both.sent, [{ type: 'blueprint/list', domain: 'automation' }, { type: 'blueprint/list', domain: 'script' }]);
  const motion = {
    domain: 'automation',
    path: 'homeassistant/motion_light.yaml',
    name: 'Motion-activated Light',
    description: 'Turn on a light when motion is detected.',
    inputs: { motion_entity: { name: 'Motion Sensor' }, hook: { name: 'Webhook', default: { api_key: M } } },
    source_url: 'https://github.com/home-assistant/core/blob/dev/homeassistant/components/automation/blueprints/motion_light.yaml',
  };
  const broken = { domain: 'automation', path: 'mine/broken.yaml', error: "Failed to load blueprint: Unable to read file mine/broken.yaml" };
  const confirm = { domain: 'script', path: 'homeassistant/confirmable_notification.yaml', name: 'Confirmable Notification', inputs: { notify_device: { name: 'Device' } } };
  assert.deepEqual(body(both.result), { total: 3, offset: 0, has_more: false, blueprints: [motion, broken, confirm] });

  const scripts = await call('ha_list_blueprints', { domain: 'script' });
  assert.deepEqual(scripts.sent, [{ type: 'blueprint/list', domain: 'script' }]);
  assert.deepEqual(body(scripts.result), { total: 1, offset: 0, has_more: false, blueprints: [confirm] });
  assert.deepEqual(body((await call('ha_list_blueprints', { limit: 1, offset: 1 })).result), { total: 3, offset: 1, has_more: true, blueprints: [broken] });
});
