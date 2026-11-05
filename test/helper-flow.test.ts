import assert from 'node:assert/strict';
import type { TestContext } from 'node:test';
import { test } from 'node:test';
import { REDACTED as M } from '../src/redaction.ts';
import { ADMIN_TOKEN, adminCaller, body, connect, fakeHa, newKey, policyOf, startServer } from './harness.ts';

const keys = Object.fromEntries(['wizard', 'helperer', 'automator'].map((name) => [name, newKey()]));
const policy = policyOf(
  keys,
  `grants:
  - caller: wizard
    config_write: helper_entry
  - caller: helperer
    config_write: helper
  - caller: automator
    config_write: automation
`,
);

/** Flows the operator has open on an integration that is not a helper: one HA discovered, one started in the UI. */
const DISCOVERED = 'd15c0e2ed15c0e2ed15c0e2ed15c0e2e';
const OPERATOR_STARTED = '0be2a7020be2a7020be2a7020be2a702';

async function house(t: TestContext) {
  const ha = await fakeHa(t, {
    flows: [
      { flow_id: DISCOVERED, handler: 'hue', source: 'zeroconf', step_id: 'user' },
      { flow_id: OPERATOR_STARTED, handler: 'hue', source: 'user', step_id: 'user' },
    ],
  });
  const server = await startServer(t, policy, ha, { HAMCP_HA_ADMIN_TOKEN: ADMIN_TOKEN, HAMCP_AUDIT_WRITES: 'true' });
  const as = async (who: string) => {
    const client = await connect(t, server.url, keys[who]!.key, 'modern');
    return { client, call: adminCaller(ha, client) };
  };
  return { ha, server, as };
}

const HELPERS = 'GET /api/config/config_entries/flow_handlers?type=helper';

test('a template sensor is created through its menu and form steps, each request with the admin token and audited by name', async (t) => {
  const { ha, server, as } = await house(t);
  const { call } = await as('wizard');

  const started = await call('ha_helper_flow', { action: 'start', handler: 'template' });
  const menu = body(started.result) as { type: string; flow_id: string; step_id: string; menu_options: string[] };
  assert.deepEqual([menu.type, menu.step_id, menu.menu_options.includes('sensor')], ['menu', 'user', true]);
  assert.deepEqual(started.sent, [{ type: HELPERS }, { type: 'POST /api/config/config_entries/flow', body: { handler: 'template' } }]);

  const { flow_id } = menu;
  const form = await call('ha_helper_flow', { action: 'step', flow_id, input: { next_step_id: 'sensor' } });
  assert.deepEqual((body(form.result) as { type: string; step_id: string }).step_id, 'sensor');
  assert.deepEqual(form.sent, [
    { type: 'config_entries/flow/progress' },
    { type: `GET /api/config/config_entries/flow/${flow_id}` },
    { type: HELPERS },
    { type: `POST /api/config/config_entries/flow/${flow_id}`, body: { next_step_id: 'sensor' } },
  ]);

  const input = { name: 'Door open minutes', state: '{{ 3 }}' };
  const done = await call('ha_helper_flow', { action: 'step', flow_id, input });
  const created = body(done.result) as { type: string; title: string; result: { entry_id: string; domain: string } };
  assert.deepEqual([created.type, created.title, created.result.domain], ['create_entry', 'Door open minutes', 'template']);
  assert.deepEqual(ha.entries.map((e) => [e.domain, e.title]), [['template', 'Door open minutes']]);

  const listed = await call('ha_helper_flow', { action: 'list' });
  const { handlers, entries } = body(listed.result) as { handlers: string[]; entries: unknown[] };
  assert.ok(handlers.includes('template') && handlers.includes('switch_as_x') && !handlers.includes('hue'));
  assert.deepEqual(entries, [{ entry_id: created.result.entry_id, domain: 'template', title: 'Door open minutes' }]);

  const named = (a: Record<string, unknown>) => [a.action, a.handler, a.flow_id, a.decision ?? a.outcome];
  assert.deepEqual(server.audits().map(named), [
    ['start', 'template', undefined, 'allow'],
    ['start', 'template', flow_id, 'done'],
    ['step', 'template', flow_id, 'allow'],
    ['step', 'template', flow_id, 'done'],
    ['step', 'template', flow_id, 'allow'],
    ['step', 'template', flow_id, 'done'],
  ]);
  assert.equal(server.audits().at(-1)?.entry_id, created.result.entry_id);
  assert.ok(server.audits().every((a) => a.kind === 'helper_entry' && a.tool === 'ha_helper_flow'));
  assert.doesNotMatch(JSON.stringify(server.audits()), /Door open|\{\{|next_step_id/, 'audit lines carry names, never step input');
});

test('a step HA rejects returns its field errors, and the same flow can be stepped again', async (t) => {
  const { ha, as } = await house(t);
  const { call } = await as('wizard');
  const { flow_id } = body((await call('ha_helper_flow', { action: 'start', handler: 'switch_as_x' })).result) as { flow_id: string };

  const rejected = await call('ha_helper_flow', { action: 'step', flow_id, input: { entity_id: 'switch.coffee_maker' } });
  assert.equal(rejected.result.isError, true);
  assert.match(JSON.stringify(rejected.result.content), /refused the input: \{\\"target_domain\\":\\"required key not provided\\"\}.*still open/);

  const done = await call('ha_helper_flow', { action: 'step', flow_id, input: { entity_id: 'switch.coffee_maker', target_domain: 'light' } });
  assert.equal((body(done.result) as { type: string }).type, 'create_entry');
  assert.deepEqual(ha.entries.map((e) => [e.domain, e.title]), [['switch_as_x', 'switch.coffee_maker']]);
});

test('a setup, step or abort of an integration HA does not list as a helper is refused and audited, with nothing sent beyond the lookups', async (t) => {
  const { ha, server, as } = await house(t);
  const { call } = await as('wizard');
  const refused = async (args: Record<string, unknown>, lookups: Record<string, unknown>[]) => {
    const { result, sent } = await call('ha_helper_flow', args);
    assert.equal(result.isError, true);
    assert.match(JSON.stringify(result.content), /does not list hue as a helper integration.*Do not retry/);
    assert.deepEqual(sent, lookups);
  };
  const progress = { type: 'config_entries/flow/progress' };
  await refused({ action: 'start', handler: 'hue' }, [{ type: HELPERS }]);
  // A discovery is named by HA's progress list, so its step is never run, even by a read.
  await refused({ action: 'step', flow_id: DISCOVERED, input: { host: '10.0.0.9' } }, [progress, { type: HELPERS }]);
  await refused({ action: 'abort', flow_id: DISCOVERED }, [progress, { type: HELPERS }]);
  const read = { type: `GET /api/config/config_entries/flow/${OPERATOR_STARTED}` };
  await refused({ action: 'step', flow_id: OPERATOR_STARTED, input: { host: '10.0.0.9' } }, [progress, read, { type: HELPERS }]);
  await refused({ action: 'abort', flow_id: OPERATOR_STARTED }, [progress, read, { type: HELPERS }]);
  assert.deepEqual(ha.flows.map((f) => [f.flow_id, f.step_id]), [[DISCOVERED, 'user'], [OPERATOR_STARTED, 'user']]);
  assert.deepEqual(ha.entries, []);

  assert.deepEqual(
    server.audits().map((a) => [a.action, a.handler, a.flow_id, a.decision, a.reason]),
    [
      ['start', 'hue', undefined, 'deny', 'not a helper integration'],
      ['step', 'hue', DISCOVERED, 'deny', 'not a helper integration'],
      ['abort', 'hue', DISCOVERED, 'deny', 'not a helper integration'],
      ['step', 'hue', OPERATOR_STARTED, 'deny', 'not a helper integration'],
      ['abort', 'hue', OPERATOR_STARTED, 'deny', 'not a helper integration'],
    ],
  );
  assert.doesNotMatch(JSON.stringify(server.audits()), /10\.0\.0\.9/);

  const gone = await call('ha_helper_flow', { action: 'abort', flow_id: 'deadbeefdeadbeef' });
  assert.match(JSON.stringify(gone.result.content), /No setup flow deadbeefdeadbeef is in progress/);
  const walk = await call('ha_helper_flow', { action: 'abort', flow_id: '../../automation/config/porch_light_1' });
  assert.match(JSON.stringify(walk.result.content), /flow_id: must be the flow_id start returned/);
  assert.deepEqual(walk.sent, []);
});

test('step input carrying the Redaction marker is refused with its path, audited by name, and nothing is sent', async (t) => {
  const { server, as } = await house(t);
  const { call } = await as('wizard');
  const { flow_id } = body((await call('ha_helper_flow', { action: 'start', handler: 'template' })).result) as { flow_id: string };
  const masked = await call('ha_helper_flow', { action: 'step', flow_id, input: { name: 'NAS', state: `{{ 'https://${M}@nas.local' }}` } });
  assert.match(JSON.stringify(masked.result.content), /input carries a redacted value at state/);
  assert.deepEqual(masked.sent, []);
  assert.deepEqual(server.audits().at(-1), { ...server.audits().at(-1), action: 'step', flow_id, decision: 'deny', reason: 'input carries a redacted value' });
});

test('a Caller holding helper, or another config-write kind, but not helper_entry, is not shown the tool and is refused and audited', async (t) => {
  const { ha, server, as } = await house(t);
  for (const who of ['helperer', 'automator']) {
    const { client, call } = await as(who);
    assert.ok(!(await client.listTools()).tools.some((d) => d.name === 'ha_helper_flow'), who);
    const denied = await call('ha_helper_flow', { action: 'start', handler: 'template' });
    assert.match(JSON.stringify(denied.result.content), /no Grant for config writes of helper_entry\. Do not retry/);
    assert.deepEqual(denied.sent, []);
  }
  assert.deepEqual(ha.flows.length, 2);
  assert.deepEqual(server.audits().map((a) => [a.caller, a.tool, a.decision]), [['helperer', 'ha_helper_flow', 'deny'], ['automator', 'ha_helper_flow', 'deny']]);
});

test('a wizard helper is never read or written as a config: only its flow makes one', async (t) => {
  const { as } = await house(t);
  const { call } = await as('wizard');
  const write = await call('ha_write_config', { kind: 'helper_entry', action: 'create', id: 'template', config: { name: 'x' } });
  const read = await call('ha_get_config', { kind: 'helper_entry', id: 'template' });
  for (const { result, sent } of [write, read]) {
    assert.match(JSON.stringify(result.content), /kind: a wizard helper is set up through its flow, not as a config/);
    assert.deepEqual(sent, []);
  }
});
