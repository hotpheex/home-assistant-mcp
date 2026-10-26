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
  { name: 'config read without an admin token', policy: `${callers}grants:\n  - caller: reader\n    read: config\n`, env: {}, error: /HAMCP_HA_ADMIN_TOKEN/ },
];
const errorsOf = (records: Record<string, unknown>[]) => records.filter((r) => r.level === 'error').map((r) => r.msg);

for (const { name, policy, error, env: extra } of refusals) {
  test(`startup refuses ${name}`, async (t) => {
    const cli = await runCli(t, ['serve'], env(policy, extra));
    assert.equal(cli.handle, undefined);
    assert.equal(await cli.exited, 1);
    const errors = errorsOf(cli.records());
    assert.match(String(errors[0]), error);
    if (extra) return;
    // A Policy error: check reports it with startup's message.
    const check = await runCli(t, ['check', writePolicy(policy)], {});
    assert.equal(await check.exited, 1);
    assert.deepEqual(errorsOf(check.records()), errors);
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

  const check = await runCli(t, ['check', writePolicy(policy)], {});
  assert.equal(await check.exited, 0);
  assert.deepEqual(
    check.records().map(({ level, msg, policy_sha256 }) => ({ level, msg, policy_sha256 })),
    cli.records().filter((r) => r.msg !== 'listening').map(({ level, msg, policy_sha256 }) => ({ level, msg, policy_sha256 })),
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

/** The names check may resolve, and the only commands it may send beyond the client's handshake and the admin check. */
const namedPolicy = (names: { area: string; label: string; domain: string; services: string }) => `${callers}grants:
  - caller: reader
    services: [${names.services}]
    targets:
      - area: ${names.area}
      - label: ${names.label}
      - domain: ${names.domain}
denies:
  - caller: reader
    services: [light.turn_on]
    targets:
      - area: ${names.area}
`;
const CHECK_COMMANDS = new Set(['supported_features', 'auth/current_user', 'get_services', 'get_states', 'extract_from_target']);

test('check, given HA, resolves every name against live HA with read-only commands', async (t) => {
  const ha = await fakeHa(t);
  // lock has entities but no services in the house, so a lock domain is still known.
  const policy = namedPolicy({ area: 'utility_room', label: 'security', domain: 'lock', services: 'light.turn_on, light.*' });
  const check = await runCli(t, ['check', writePolicy(policy)], { HAMCP_HA_URL: ha.url, HAMCP_HA_USERS_TOKEN: USERS_TOKEN });
  assert.equal(await check.exited, 0, check.lines.join('\n'));
  assert.deepEqual(errorsOf(check.records()), []);
  assert.ok(ha.received.some((r) => r.message.type === 'extract_from_target'));
  assert.deepEqual(ha.received.map((r) => r.message.type).filter((type) => !CHECK_COMMANDS.has(type)), []);
  assert.deepEqual(new Set(ha.received.map((r) => r.token)), new Set([USERS_TOKEN]));
});

test('check, given HA, reports every unknown area, label, domain and service as an error', async (t) => {
  const ha = await fakeHa(t);
  const policy = namedPolicy({ area: 'utilty_room', label: 'securty', domain: 'lok', services: 'light.turn_onn, ligt.*' });
  const check = await runCli(t, ['check', writePolicy(policy)], { HAMCP_HA_URL: ha.url, HAMCP_HA_USERS_TOKEN: USERS_TOKEN });
  assert.equal(await check.exited, 1);
  assert.deepEqual(errorsOf(check.records()), [
    'grants.0.services.0: Home Assistant has no service "light.turn_onn"',
    'grants.0.services.1: Home Assistant has no domain "ligt"',
    'grants.0.targets.0.area: Home Assistant has no area "utilty_room"',
    'grants.0.targets.1.label: Home Assistant has no label "securty"',
    'grants.0.targets.2.domain: Home Assistant has no domain "lok"',
    'denies.0.targets.0.area: Home Assistant has no area "utilty_room"',
  ]);
  assert.deepEqual(ha.received.map((r) => r.message.type).filter((type) => !CHECK_COMMANDS.has(type)), []);
});
