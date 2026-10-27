import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { test } from 'node:test';
import { body, connect, fakeHa, newKey, policyOf, runImage, USERS_TOKEN, writePolicy } from './harness.ts';

/** The built image under test; CI builds one and sets this, and without it there is nothing to run. */
const image = process.env.HAMCP_IMAGE;

test('the image serves as UID 65532 on a read-only root filesystem', { skip: !image && 'HAMCP_IMAGE is not set' }, async (t) => {
  const ha = await fakeHa(t);
  const reader = newKey();
  const policy = writePolicy(policyOf({ reader }, 'grants:\n  - caller: reader\n    read: plain\n'));
  const server = runImage(image!, policy, { HAMCP_HA_URL: ha.url, HAMCP_HA_USERS_TOKEN: USERS_TOKEN }, (fn) => t.after(fn));

  await server.logged('connected to Home Assistant', 30_000);
  const client = await connect(t, server.url(), reader.key, 'modern');
  const result = await client.callTool({ name: 'ha_get_states', arguments: { domain: 'lock' } });
  assert.equal((body(result) as { total: number }).total, 1);

  const uid = execFileSync('docker', ['exec', server.name, '/nodejs/bin/node', '-p', 'process.getuid()'], { encoding: 'utf8' });
  assert.equal(uid.trim(), '65532');
});
