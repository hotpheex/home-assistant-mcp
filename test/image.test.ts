import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import { test } from 'node:test';
import { body, connect, fakeHa, newKey, until, USERS_TOKEN, writePolicy } from './harness.ts';

/** The built image under test; CI builds one and sets this, and without it there is nothing to run. */
const image = process.env.HAMCP_IMAGE;

test('the image serves as UID 65532 on a read-only root filesystem', { skip: !image && 'HAMCP_IMAGE is not set' }, async (t) => {
  const ha = await fakeHa(t);
  const reader = newKey();
  const policy = writePolicy(`version: 1
callers:
  reader:
    keys:
      - sha256: ${reader.sha256}
grants:
  - caller: reader
    read: plain
`);
  const name = `hamcp-image-test-${process.pid}`;
  // Host networking lets the container reach the in-process fake HA on loopback.
  const container = spawn('docker', [
    'run', '--rm', '--name', name, '--read-only', '--network', 'host',
    '--volume', `${policy}:/policy.yaml:ro`,
    '--env', 'HAMCP_POLICY=/policy.yaml',
    '--env', `HAMCP_HA_URL=${ha.url}`,
    '--env', `HAMCP_HA_USERS_TOKEN=${USERS_TOKEN}`,
    '--env', 'HAMCP_LISTEN=127.0.0.1:0',
    image!,
  ], { stdio: ['ignore', 'pipe', 'inherit'] });
  t.after(() => {
    spawnSync('docker', ['rm', '--force', name], { stdio: 'ignore' });
  });
  const records: Record<string, unknown>[] = [];
  createInterface({ input: container.stdout }).on('line', (line) => records.push(JSON.parse(line) as Record<string, unknown>));

  await until(() => records.some((r) => r.msg === 'connected to Home Assistant'), 'HA connection', 30_000);
  const address = records.find((r) => r.msg === 'listening')?.address;
  const client = await connect(t, `http://${String(address)}/mcp`, reader.key, 'modern');
  const result = await client.callTool({ name: 'ha_get_states', arguments: { domain: 'lock' } });
  assert.equal((body(result) as { total: number }).total, 1);

  const uid = execFileSync('docker', ['exec', name, '/nodejs/bin/node', '-p', 'process.getuid()'], { encoding: 'utf8' });
  assert.equal(uid.trim(), '65532');
});
