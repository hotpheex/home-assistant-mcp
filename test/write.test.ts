import assert from 'node:assert/strict';
import type { TestContext } from 'node:test';
import { test } from 'node:test';
import { ADMIN_TOKEN, body, connect, fakeHa, newKey, startServer } from './harness.ts';

const keys = Object.fromEntries(['auditor', 'automator', 'scripter', 'scener', 'helperer'].map((name) => [name, newKey()]));
const policy = `
version: 1
callers:
${Object.entries(keys).map(([name, { sha256 }]) => `  ${name}:\n    keys: [{ sha256: ${sha256} }]`).join('\n')}
grants:
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
`;

async function house(t: TestContext) {
  const ha = await fakeHa(t);
  const server = await startServer(t, policy, ha, { HAMCP_HA_ADMIN_TOKEN: ADMIN_TOKEN, HAMCP_AUDIT_WRITES: 'true' });
  /** Calls a tool as `who`, returning the result and what reached HA, all of it at the admin tier. */
  const as = async (who: string) => {
    const client = await connect(t, server.url, keys[who]!.key, 'modern');
    const call = async (name: string, args: Record<string, unknown>) => {
      const before = ha.received.length;
      const result = await client.callTool({ name, arguments: args });
      const sent = ha.received.slice(before);
      assert.ok(sent.every((r) => r.token === ADMIN_TOKEN));
      assert.doesNotMatch(JSON.stringify(result), /SECRET/);
      return { result, sent: sent.map((r) => Object.fromEntries(Object.entries(r.message).filter(([k]) => k !== 'id'))) };
    };
    return { client, call };
  };
  return { ha, server, as };
}

const NEW_AUTOMATION = { alias: 'Hall light', triggers: [{ trigger: 'sun', event: 'sunset' }], actions: [{ action: 'light.turn_on' }] };

test('a config-write Grant lists ha_write_config, described as admin-equivalent; config read does not', async (t) => {
  const { as } = await house(t);
  const listed = (await (await as('automator')).client.listTools()).tools;
  const definition = listed.find((d) => d.name === 'ha_write_config');
  assert.match(definition?.description ?? '', /admin-equivalent/);
  assert.deepEqual(Object.keys(definition?.inputSchema.properties ?? {}).sort(), ['action', 'config', 'id', 'kind']);
  const auditing = (await (await as('auditor')).client.listTools()).tools;
  assert.equal(auditing.some((d) => d.name === 'ha_write_config'), false);
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
