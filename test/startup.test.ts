import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { ADMIN_TOKEN, connect, fakeHa, newKey, runCli, startServer, until, USERS_TOKEN, writePolicy } from './harness.ts';

const key = newKey();
const callers = `
version: 1
callers:
  reader:
    keys:
      - sha256: ${key.sha256}
`;
const env = (policy: string, extra: Record<string, string | undefined> = {}) => ({
  HAMCP_POLICY: writePolicy(policy),
  HAMCP_HA_URL: 'http://127.0.0.1:9',
  HAMCP_HA_USERS_TOKEN: USERS_TOKEN,
  HAMCP_LISTEN: '127.0.0.1:0',
  ...extra,
});

const refusals = [
  { name: 'an unknown field', policy: `${callers}grants:\n  - caller: reader\n    read: plain\n    scope: all\n`, error: /scope/ },
  { name: 'a malformed key hash', policy: callers.replace(key.sha256, key.sha256.slice(1)), error: /sha256/ },
  { name: 'an undeclared Caller', policy: `${callers}grants:\n  - caller: ghost\n    read: plain\n`, error: /"ghost" is not declared/ },
  {
    name: 'one key hash on two Callers',
    policy: `${callers}  twin:\n    keys:\n      - sha256: ${key.sha256}\n`,
    error: /already bound to Caller "reader"/,
  },
  { name: 'a homeassistant.* service', policy: `${callers}grants:\n  - caller: reader\n    services: [homeassistant.*]\n`, error: /homeassistant/ },
  { name: 'a bare * service', policy: `${callers}denies:\n  - caller: reader\n    services: ['*']\n`, error: /bare \*/ },
  {
    name: 'an HAMCP_AUDIT_READS that is not a boolean',
    policy: `${callers}grants:\n  - caller: reader\n    read: plain\n`,
    env: { HAMCP_AUDIT_READS: 'maybe' },
    error: /HAMCP_AUDIT_READS/,
  },
  {
    name: 'a missing token for a needed tier',
    policy: `${callers}grants:\n  - caller: reader\n    read: plain\n`,
    env: { HAMCP_HA_USERS_TOKEN: undefined },
    error: /HAMCP_HA_USERS_TOKEN/,
  },
  { name: 'config read without an admin token', policy: `${callers}grants:\n  - caller: reader\n    read: config\n`, error: /HAMCP_HA_ADMIN_TOKEN/ },
];

for (const { name, policy, error, env: extra } of refusals) {
  test(`startup refuses ${name}`, async (t) => {
    const cli = await runCli(t, ['serve'], env(policy, extra));
    assert.equal(cli.handle, undefined);
    assert.equal(await cli.exited, 1);
    const errors = cli.records().filter((r) => r.level === 'error');
    assert.match(String(errors[0]?.msg), error);
  });
}

test('a valid Policy logs its SHA-256 digest, and warns about Policy that does nothing', async (t) => {
  const lapsed = newKey();
  const policy = `${callers}  lapsed:
    keys:
      - sha256: ${lapsed.sha256}
        expires: 2020-01-01
grants:
  - caller: reader
    services: [light.*]
denies:
  - caller: reader
    services: [lock.unlock]
  - caller: reader
    services: [light.turn_on]
`;
  const cli = await runCli(t, ['serve'], env(policy));
  assert.ok(cli.handle);
  const loaded = cli.records().find((r) => r.msg === 'policy loaded');
  assert.equal(loaded?.policy_sha256, createHash('sha256').update(policy).digest('hex'));
  assert.deepEqual(
    cli
      .records()
      .filter((r) => r.level === 'warn')
      .map((r) => r.msg),
    ['Caller "lapsed" has no unexpired key and can never authenticate', 'denies.0 overlaps no grant of Caller "reader" and does nothing'],
  );
});

test('keygen prints a 256-bit hamcp_ key and its SHA-256 hash', async (t) => {
  const cli = await runCli(t, ['keygen'], {});
  const [keyLine, hashLine] = cli.lines;
  const printed = /^key: (hamcp_(\S+))$/.exec(keyLine ?? '');
  assert.ok(printed?.[1] && printed[2]);
  assert.equal(Buffer.from(printed[2], 'base64url').length, 32);
  assert.equal(hashLine, `sha256: ${createHash('sha256').update(printed[1]).digest('hex')}`);
});

const grantsPlainRead = `${callers}grants:\n  - caller: reader\n    read: plain\n`;

test('the server exits when HA is below 2026.10', async (t) => {
  const ha = await fakeHa(t, { version: '2026.9.3' });
  const cli = await runCli(t, ['serve'], env(grantsPlainRead, { HAMCP_HA_URL: ha.url }));
  assert.equal(await cli.exited, 1);
  assert.ok(cli.records().some((r) => r.level === 'error' && /2026\.9\.3 is below/.test(String(r.msg))));
});

test('the server exits when the users-tier token belongs to an HA admin', async (t) => {
  const ha = await fakeHa(t);
  const cli = await runCli(t, ['serve'], env(grantsPlainRead, { HAMCP_HA_URL: ha.url, HAMCP_HA_USERS_TOKEN: ADMIN_TOKEN }));
  assert.equal(await cli.exited, 1);
  assert.ok(cli.records().some((r) => r.level === 'error' && /admin/.test(String(r.msg))));
  assert.ok(!ha.received.some((r) => r.message.type === 'get_states'));
});

test('the server warns but serves when HA is newer than the tested release', async (t) => {
  const ha = await fakeHa(t, { version: '2026.11.0' });
  const server = await startServer(t, grantsPlainRead, ha);
  await until(() => server.records().some((r) => r.level === 'warn' && r.ha_version === '2026.11.0'), 'newer-HA warning');
});

test('an admin token no Grant needs is warned about and never used', async (t) => {
  const ha = await fakeHa(t);
  const server = await startServer(t, grantsPlainRead, ha, { HAMCP_HA_ADMIN_TOKEN: ADMIN_TOKEN });
  const client = await connect(t, server.url, key.key, 'modern');
  await client.callTool({ name: 'ha_get_states', arguments: {} });
  assert.ok(server.records().some((r) => r.level === 'warn' && /HAMCP_HA_ADMIN_TOKEN/.test(String(r.msg))));
  assert.deepEqual(new Set(ha.received.map((r) => r.token)), new Set([USERS_TOKEN]));
});
