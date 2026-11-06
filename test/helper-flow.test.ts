import assert from 'node:assert/strict';
import type { TestContext } from 'node:test';
import { test } from 'node:test';
import { REDACTED as M } from '../src/redaction.ts';
import type { FakeHaOptions } from './fake-ha.ts';
import { ADMIN_TOKEN, adminCaller, body, connect, fakeHa, HUE_ENTRY, newKey, policyOf, startServer, TEMPLATE_ENTRY, WIZARD_ENTRIES } from './harness.ts';

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

/** Flows the operator has open: two HA discovered, the second for a helper integration, and one started in the UI. */
const DISCOVERED = 'd15c0e2ed15c0e2ed15c0e2ed15c0e2e';
const DISCOVERED_HELPER = 'd15c0e2e7e3f1a7ed15c0e2e7e3f1a7e';
const OPERATOR_STARTED = '0be2a7020be2a7020be2a7020be2a702';

async function house(t: TestContext, seed: Partial<FakeHaOptions> = {}) {
  const ha = await fakeHa(t, {
    flows: [
      { flow_id: DISCOVERED, handler: 'hue', source: 'zeroconf', step_id: 'user' },
      { flow_id: DISCOVERED_HELPER, handler: 'template', source: 'zeroconf', step_id: 'user' },
      { flow_id: OPERATOR_STARTED, handler: 'hue', source: 'user', step_id: 'user' },
    ],
    ...seed,
  });
  const server = await startServer(t, policy, ha, { HAMCP_HA_ADMIN_TOKEN: ADMIN_TOKEN, HAMCP_AUDIT_WRITES: 'true', HAMCP_AUDIT_READS: 'true' });
  const as = async (who: string) => {
    const client = await connect(t, server.url, keys[who]!.key, 'modern');
    return { client, call: adminCaller(ha, client) };
  };
  return { ha, server, as };
}

const HELPERS = 'GET /api/config/config_entries/flow_handlers?type=helper';

test('a template sensor is created through its menu and form steps, each request with the admin token and audited by name; a list is a read', async (t) => {
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
  // A list is a read, so it is audited only on the reads opt-in, and an oversize one is refused whole.
  ha.entries.push({ ...ha.entries[0]!, entry_id: 'big', title: 'x'.repeat(48_000) });
  const oversize = await call('ha_helper_flow', { action: 'list' });
  assert.match(JSON.stringify(oversize.result.content), /over 48000 characters, so nothing was returned, and this tool offers no narrower query/);
  const reads = server.audits().filter((a) => a.request !== undefined);
  assert.deepEqual(reads.map((a) => [a.decision, a.request]), [['allow', { action: 'list' }], ['allow', { action: 'list' }]]);

  const named = (a: Record<string, unknown>) => [a.action, a.handler, a.flow_id, a.decision ?? a.outcome];
  const writes = server.audits().filter((a) => a.request === undefined);
  assert.deepEqual(writes.map(named), [
    ['start', 'template', undefined, 'allow'],
    ['start', 'template', flow_id, 'done'],
    ['step', 'template', flow_id, 'allow'],
    ['step', 'template', flow_id, 'done'],
    ['step', 'template', flow_id, 'allow'],
    ['step', 'template', flow_id, 'done'],
  ]);
  assert.equal(writes.at(-1)?.entry_id, created.result.entry_id);
  assert.ok(writes.every((a) => a.kind === 'helper_entry' && a.tool === 'ha_helper_flow'));
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

test('a setup, step or abort of a discovery, or of an integration HA does not list as a helper, is refused and audited, with nothing sent beyond the lookups', async (t) => {
  const { ha, server, as } = await house(t);
  const { call } = await as('wizard');
  const refused = async (args: Record<string, unknown>, lookups: Record<string, unknown>[], why = /does not list hue as a helper integration.*Do not retry/) => {
    const { result, sent } = await call('ha_helper_flow', args);
    assert.equal(result.isError, true);
    assert.match(JSON.stringify(result.content), why);
    assert.deepEqual(sent, lookups);
  };
  const progress = { type: 'config_entries/flow/progress' };
  await refused({ action: 'start', handler: 'hue' }, [{ type: HELPERS }]);
  // A discovery is named by HA's progress list, so its step is never run, even by a read, whatever its integration.
  const discovery = /Home Assistant started flow \w+ itself, such as a discovery.*Do not retry/;
  for (const flow_id of [DISCOVERED, DISCOVERED_HELPER]) {
    await refused({ action: 'step', flow_id, input: { host: '10.0.0.9' } }, [progress, { type: HELPERS }], discovery);
    await refused({ action: 'abort', flow_id }, [progress, { type: HELPERS }], discovery);
  }
  const read = { type: `GET /api/config/config_entries/flow/${OPERATOR_STARTED}` };
  await refused({ action: 'step', flow_id: OPERATOR_STARTED, input: { host: '10.0.0.9' } }, [progress, read, { type: HELPERS }]);
  await refused({ action: 'abort', flow_id: OPERATOR_STARTED }, [progress, read, { type: HELPERS }]);
  assert.deepEqual(ha.flows.map((f) => [f.flow_id, f.step_id]), [[DISCOVERED, 'user'], [DISCOVERED_HELPER, 'user'], [OPERATOR_STARTED, 'user']]);
  assert.deepEqual(ha.entries, []);

  assert.deepEqual(
    server.audits().map((a) => [a.action, a.handler, a.flow_id, a.decision, a.reason]),
    [
      ['start', 'hue', undefined, 'deny', 'not a helper integration'],
      ['step', 'hue', DISCOVERED, 'deny', 'a discovery'],
      ['abort', 'hue', DISCOVERED, 'deny', 'a discovery'],
      ['step', 'template', DISCOVERED_HELPER, 'deny', 'a discovery'],
      ['abort', 'template', DISCOVERED_HELPER, 'deny', 'a discovery'],
      ['step', 'hue', OPERATOR_STARTED, 'deny', 'not a helper integration'],
      ['abort', 'hue', OPERATOR_STARTED, 'deny', 'not a helper integration'],
    ],
  );
  assert.doesNotMatch(JSON.stringify(server.audits()), /10\.0\.0\.9/);

  const gone = await call('ha_helper_flow', { action: 'abort', flow_id: 'deadbeefdeadbeef' });
  assert.match(JSON.stringify(gone.result.content), /No setup or options flow deadbeefdeadbeef is in progress/);
  const walk = await call('ha_helper_flow', { action: 'abort', flow_id: '../../automation/config/porch_light_1' });
  assert.match(JSON.stringify(walk.result.content), /flow_id: must be the flow_id start or edit returned/);
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
  assert.deepEqual(ha.flows.length, 3);
  assert.deepEqual(server.audits().map((a) => [a.caller, a.tool, a.decision]), [['helperer', 'ha_helper_flow', 'deny'], ['automator', 'ha_helper_flow', 'deny']]);
});

test('a wizard helper is never read or written as a config: a Caller holding only helper_entry is not shown the config write, and only its flow makes one', async (t) => {
  const { server, as } = await house(t);
  const { client, call } = await as('wizard');
  assert.ok(!(await client.listTools()).tools.some((d) => d.name === 'ha_write_config'));
  const hidden = await call('ha_write_config', { kind: 'helper_entry', action: 'create', id: 'template', config: { name: 'x' } });
  assert.match(JSON.stringify(hidden.result.content), /no Grant for config writes of automation or script or scene or helper or entity_name or zone or dashboard\. Do not retry/);
  assert.deepEqual(server.audits().map((a) => [a.caller, a.tool, a.decision]), [['wizard', 'ha_write_config', 'deny']]);
  const write = await (await as('automator')).call('ha_write_config', { kind: 'helper_entry', action: 'create', id: 'template', config: { name: 'x' } });
  const read = await call('ha_get_config', { kind: 'helper_entry', id: 'template' });
  for (const { result, sent } of [write, read]) {
    assert.match(JSON.stringify(result.content), /kind: a wizard helper is set up through its flow, not as a config/);
    assert.deepEqual(sent, []);
  }
  assert.deepEqual(hidden.sent, []);
});

const progress = { type: 'config_entries/flow/progress' };
const entryOf = (entry_id: string) => ({ type: 'config_entries/get_single', entry_id });

test("a template sensor's state template is changed through its options form, and a wizard helper is deleted, each request with the admin token and audited by entry id", async (t) => {
  const { ha, server, as } = await house(t, WIZARD_ENTRIES);
  const { call } = await as('wizard');

  const edit = await call('ha_helper_flow', { action: 'edit', entry_id: TEMPLATE_ENTRY });
  const form = body(edit.result) as { type: string; flow_id: string; step_id: string; handler: string };
  assert.deepEqual([form.type, form.step_id, form.handler], ['form', 'sensor', TEMPLATE_ENTRY]);
  const { flow_id } = form;
  assert.deepEqual(edit.sent, [entryOf(TEMPLATE_ENTRY), { type: HELPERS }, { type: 'POST /api/config/config_entries/options/flow', body: { handler: TEMPLATE_ENTRY } }]);

  const step = await call('ha_helper_flow', { action: 'step', flow_id, input: { state: '{{ 4 }}' } });
  assert.equal((body(step.result) as { type: string }).type, 'create_entry');
  // A flow the Caller started is not in the progress list, and is not a config flow, so HA names its entry only when asked for it as an options flow.
  assert.deepEqual(step.sent, [
    progress,
    { type: `GET /api/config/config_entries/flow/${flow_id}` },
    { type: `GET /api/config/config_entries/options/flow/${flow_id}` },
    entryOf(TEMPLATE_ENTRY),
    { type: HELPERS },
    { type: `POST /api/config/config_entries/options/flow/${flow_id}`, body: { state: '{{ 4 }}' } },
  ]);
  assert.equal(ha.entries.find((e) => e.entry_id === TEMPLATE_ENTRY)?.options.state, '{{ 4 }}');

  const second = body((await call('ha_helper_flow', { action: 'edit', entry_id: TEMPLATE_ENTRY })).result) as { flow_id: string };
  const aborted = await call('ha_helper_flow', { action: 'abort', flow_id: second.flow_id });
  assert.equal(aborted.sent.at(-1)?.type, `DELETE /api/config/config_entries/options/flow/${second.flow_id}`);
  assert.deepEqual(ha.optionsFlows, []);

  const deleted = await call('ha_helper_flow', { action: 'delete', entry_id: TEMPLATE_ENTRY });
  assert.deepEqual(body(deleted.result), { require_restart: false });
  assert.deepEqual(deleted.sent, [entryOf(TEMPLATE_ENTRY), { type: HELPERS }, { type: `DELETE /api/config/config_entries/entry/${TEMPLATE_ENTRY}` }]);
  assert.deepEqual(ha.entries.map((e) => e.entry_id), [HUE_ENTRY]);

  const named = (a: Record<string, unknown>) => [a.action, a.handler, a.entry_id, a.flow_id, a.decision ?? a.outcome];
  assert.deepEqual(server.audits().map(named), [
    ['edit', 'template', TEMPLATE_ENTRY, undefined, 'allow'],
    ['edit', 'template', TEMPLATE_ENTRY, flow_id, 'done'],
    ['step', 'template', TEMPLATE_ENTRY, flow_id, 'allow'],
    ['step', 'template', TEMPLATE_ENTRY, flow_id, 'done'],
    ['edit', 'template', TEMPLATE_ENTRY, undefined, 'allow'],
    ['edit', 'template', TEMPLATE_ENTRY, second.flow_id, 'done'],
    ['abort', 'template', TEMPLATE_ENTRY, second.flow_id, 'allow'],
    ['abort', 'template', TEMPLATE_ENTRY, second.flow_id, 'done'],
    ['delete', 'template', TEMPLATE_ENTRY, undefined, 'allow'],
    ['delete', 'template', TEMPLATE_ENTRY, undefined, 'done'],
  ]);
  assert.doesNotMatch(JSON.stringify(server.audits()), /\{\{/, 'audit lines carry names, never step input');
});

test('an edit, delete, step or abort on the entry of an integration HA does not list as a helper is refused and audited, with nothing sent beyond the lookups', async (t) => {
  const HUE_OPTIONS = '0b7105f10b7105f10b7105f10b7105f1';
  const { ha, server, as } = await house(t, { ...WIZARD_ENTRIES, optionsFlows: [{ flow_id: HUE_OPTIONS, handler: HUE_ENTRY, source: 'user', step_id: 'init' }] });
  const { call } = await as('wizard');
  const refused = async (args: Record<string, unknown>, lookups: Record<string, unknown>[]) => {
    const { result, sent } = await call('ha_helper_flow', args);
    assert.match(JSON.stringify(result.content), /does not list hue as a helper integration.*Do not retry/);
    assert.deepEqual(sent, lookups);
  };
  await refused({ action: 'edit', entry_id: HUE_ENTRY }, [entryOf(HUE_ENTRY), { type: HELPERS }]);
  await refused({ action: 'delete', entry_id: HUE_ENTRY }, [entryOf(HUE_ENTRY), { type: HELPERS }]);
  const lookups = [progress, { type: `GET /api/config/config_entries/flow/${HUE_OPTIONS}` }, { type: `GET /api/config/config_entries/options/flow/${HUE_OPTIONS}` }, entryOf(HUE_ENTRY), { type: HELPERS }];
  await refused({ action: 'step', flow_id: HUE_OPTIONS, input: { allow_hue_groups: true } }, lookups);
  await refused({ action: 'abort', flow_id: HUE_OPTIONS }, lookups);
  assert.deepEqual(ha.entries.map((e) => [e.entry_id, e.options]), [[TEMPLATE_ENTRY, WIZARD_ENTRIES.entries![0]!.options], [HUE_ENTRY, {}]]);
  assert.deepEqual(ha.optionsFlows.map((f) => f.flow_id), [HUE_OPTIONS]);
  assert.deepEqual(
    server.audits().map((a) => [a.action, a.handler, a.entry_id, a.flow_id, a.decision, a.reason]),
    [
      ['edit', 'hue', HUE_ENTRY, undefined, 'deny', 'not a helper integration'],
      ['delete', 'hue', HUE_ENTRY, undefined, 'deny', 'not a helper integration'],
      ['step', 'hue', HUE_ENTRY, HUE_OPTIONS, 'deny', 'not a helper integration'],
      ['abort', 'hue', HUE_ENTRY, HUE_OPTIONS, 'deny', 'not a helper integration'],
    ],
  );

  const missing = await call('ha_helper_flow', { action: 'delete', entry_id: '01K9N0SUCHENTRY00000000000' });
  assert.match(JSON.stringify(missing.result.content), /No entry 01K9N0SUCHENTRY00000000000 exists/);
  assert.deepEqual(missing.sent, [entryOf('01K9N0SUCHENTRY00000000000')]);
  const walk = await call('ha_helper_flow', { action: 'delete', entry_id: '../../automation/config/porch_light_1' });
  assert.match(JSON.stringify(walk.result.content), /entry_id: must be an entry_id list returned/);
  assert.deepEqual(walk.sent, []);
});
