import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { parse } from 'yaml';
import * as z from 'zod';
import { policyJsonSchema } from '../src/policy.ts';
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

test('the published JSON Schema accepts a valid Policy and rejects an unknown field', () => {
  const schema = z.fromJSONSchema(policyJsonSchema());
  const valid = `${callers}        expires: 2030-01-01
grants:
  - caller: reader
    read: config
  - caller: reader
    services: [light.turn_on, switch.*]
    targets:
      - area: kitchen
      - domain: '*'
  - caller: reader
    config_write: helper
denies:
  - caller: reader
    services: [switch.turn_off]
    targets:
      - label: critical
`;
  assert.equal(schema.safeParse(parse(valid)).success, true);
  assert.equal(schema.safeParse(parse(refusals[0]!.policy)).success, false);
});

test('a valid Policy logs its SHA-256 digest; once HA is reachable it warns about Policy that does nothing and names HA lacks', async (t) => {
  const lapsed = newKey();
  const policy = `${callers}  lapsed:
    keys:
      - sha256: ${lapsed.sha256}
        expires: 2020-01-01
grants:
  - caller: reader
    services: [light.*, vacuum.start]
    targets:
      - area: utility_room
      - area: attic
      - label: security
      - domain: sprinkler
denies:
  - caller: reader
    services: [switch.turn_on]
  - caller: reader
    services: [light.turn_on]
    targets:
      - label: garden
`;
  const ha = await fakeHa(t);
  const down = ha.outage();
  const cli = await runCli(t, ['serve'], env(policy, { HAMCP_HA_URL: ha.url }));
  await down;
  const digest = createHash('sha256').update(policy).digest('hex');
  assert.equal(cli.records().find((r) => r.msg === 'policy loaded')?.policy_sha256, digest);
  const warnings = () => cli.records().filter((r) => r.level === 'warn').map((r) => r.msg);
  assert.deepEqual(warnings(), []);

  ha.restore();
  const doesNothing = ['Caller "lapsed" has no unexpired key and can never authenticate', 'denies.0 overlaps no grant of Caller "reader" and does nothing'];
  await until(() => warnings().length >= 7, 'startup warnings', 5000);
  assert.deepEqual(warnings(), [
    ...doesNothing,
    'grants.0.services.1: Home Assistant has no service "vacuum.start"',
    'grants.0.targets.1.area: Home Assistant has no area "attic"',
    'grants.0.targets.3.domain: Home Assistant has no domain "sprinkler"',
    'denies.0.services.0: Home Assistant has no service "switch.turn_on"',
    'denies.1.targets.0.label: Home Assistant has no label "garden"',
  ]);

  const check = await runCli(t, ['check', writePolicy(policy)], {});
  assert.equal(await check.exited, 0);
  assert.deepEqual(
    check.records().map(({ level, msg, policy_sha256 }) => ({ level, msg, policy_sha256 })),
    [{ level: 'info', msg: 'policy loaded', policy_sha256: digest }, ...doesNothing.map((msg) => ({ level: 'warn', msg, policy_sha256: undefined }))],
  );
});

test('a key within 14 days of expiry is warned about at startup and daily', async (t) => {
  t.mock.timers.enable({ apis: ['setInterval'] });
  const inDays = (n: number) => new Date(Date.now() + n * 86_400_000).toISOString().slice(0, 10);
  const soon = newKey();
  const later = newKey();
  const policy = `${callers}  rotating:
    keys:
      - sha256: ${soon.sha256}
        expires: ${inDays(10)}
      - sha256: ${later.sha256}
        expires: ${inDays(20)}
`;
  const cli = await runCli(t, ['serve'], env(policy));
  const warnings = () => cli.records().filter((r) => r.level === 'warn').map((r) => r.msg);
  const expiring = `Caller "rotating" key ${soon.sha256.slice(0, 8)} expires on ${inDays(10)}; add a new key and move the Caller to it`;
  assert.deepEqual(warnings(), [expiring]);
  t.mock.timers.tick(86_400_000);
  assert.deepEqual(warnings(), [expiring, expiring]);
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

const whileRunning = [
  { name: 'HA rejects its token', change: { revoke: USERS_TOKEN }, error: /rejected the users-tier token/ },
  { name: 'a reconnect finds HA below 2026.10', change: { version: '2026.9.3' }, error: /2026\.9\.3 is below/ },
];
for (const { name, change, error } of whileRunning) {
  test(`the running server exits non-zero when ${name}`, async (t) => {
    const ha = await fakeHa(t);
    const server = await startServer(t, grantsPlainRead, ha);
    ha.restart(change);
    assert.equal(await server.exited, 1);
    assert.ok(server.records().some((r) => r.level === 'error' && error.test(String(r.msg))));
  });
}

test('the server exits when the users-tier token belongs to an HA admin', async (t) => {
  const ha = await fakeHa(t);
  const cli = await runCli(t, ['serve'], env(grantsPlainRead, { HAMCP_HA_URL: ha.url, HAMCP_HA_USERS_TOKEN: ADMIN_TOKEN }));
  assert.equal(await cli.exited, 1);
  assert.ok(cli.records().some((r) => r.level === 'error' && /admin/.test(String(r.msg))));
  assert.ok(!ha.received.some((r) => r.message.type === 'get_states'));
});

/** The pinned-stable HA the PR workflow's e2e runs against, which Renovate bumps. */
const pinnedStable = /# renovate: pinned-stable HA\n\s*[\w-]+:\s*(\d+)\.(\d+)\.\d+/.exec(
  readFileSync(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8'),
);

test('the server serves the pinned-stable HA without a warning, and warns but serves when HA is newer', async (t) => {
  assert.ok(pinnedStable, 'ci.yml pins a stable HA');
  const [, year, month] = pinnedStable.map(Number);
  const newer = `${year! + 1}.1.0`;
  for (const version of [`${year}.${month}.0`, newer]) {
    const ha = await fakeHa(t, { version });
    const server = await startServer(t, grantsPlainRead, ha);
    assert.equal(server.records().some((r) => r.level === 'warn' && r.ha_version === version), version === newer, version);
  }
});

test('an admin token no Grant needs is warned about and never used', async (t) => {
  const ha = await fakeHa(t);
  const server = await startServer(t, grantsPlainRead, ha, { HAMCP_HA_ADMIN_TOKEN: ADMIN_TOKEN });
  const client = await connect(t, server.url, key.key, 'modern');
  await client.callTool({ name: 'ha_get_states', arguments: {} });
  assert.ok(server.records().some((r) => r.level === 'warn' && /HAMCP_HA_ADMIN_TOKEN/.test(String(r.msg))));
  assert.deepEqual(new Set(ha.received.map((r) => r.token)), new Set([USERS_TOKEN]));
});

/** What an orchestrator's probe sees: the status and body, with no key. */
async function probe(address: string, path: '/healthz' | '/readyz') {
  const res = await fetch(`http://${address}${path}`);
  return { status: res.status, body: await res.text() };
}

test('the server listens while HA is down, reports readiness from its HA connections, and reconnects with backoff', async (t) => {
  const ha = await fakeHa(t);
  const down = ha.outage();
  const cli = await runCli(t, ['serve'], env(grantsPlainRead, { HAMCP_HA_URL: ha.url }));
  await down;
  const address = cli.handle!.address;
  assert.deepEqual(await probe(address, '/healthz'), { status: 200, body: '' });
  assert.deepEqual(await probe(address, '/readyz'), { status: 503, body: '' });

  ha.restore();
  await until(() => cli.records().some((r) => r.msg === 'connected to Home Assistant'), 'HA connection', 5000);
  assert.deepEqual(await probe(address, '/readyz'), { status: 200, body: '' });

  await ha.outage();
  assert.deepEqual(await probe(address, '/readyz'), { status: 503, body: '' });
  assert.deepEqual(await probe(address, '/healthz'), { status: 200, body: '' });
  ha.restore();
  await until(() => cli.records().filter((r) => r.msg === 'connected to Home Assistant').length === 2, 'HA reconnection', 5000);
  assert.deepEqual(await probe(address, '/readyz'), { status: 200, body: '' });
});

test('a heartbeat finds a half-open connection: the call waiting on it fails with "HA unavailable" and readiness drops', async (t) => {
  t.mock.timers.enable({ apis: ['setInterval'] });
  const ha = await fakeHa(t);
  const server = await startServer(t, grantsPlainRead, ha);
  const client = await connect(t, server.url, key.key, 'modern');
  ha.hang();
  const pending = client.callTool({ name: 'ha_get_states', arguments: {} });
  await until(() => ha.received.some((r) => r.message.type === 'get_states'), 'the read to reach HA');
  t.mock.timers.tick(30_000);
  await until(() => ha.received.some((r) => r.message.type === 'ping'), 'a heartbeat ping');
  t.mock.timers.tick(30_000);
  const result = (await pending) as { content: { text: string }[] };
  assert.equal(result.content[0]?.text, 'HA unavailable: nothing was sent to Home Assistant. Try again later.');
  assert.deepEqual(await probe(server.handle!.address, '/readyz'), { status: 503, body: '' });
});

test('readiness waits for every needed tier, and a connection lost during the checks is retried rather than fatal', async (t) => {
  const ha = await fakeHa(t);
  ha.drop.add('auth/current_user');
  const policy = `${grantsPlainRead}  - caller: reader\n    read: config\n`;
  const cli = await runCli(t, ['serve'], env(policy, { HAMCP_HA_URL: ha.url, HAMCP_HA_ADMIN_TOKEN: ADMIN_TOKEN }));
  const address = cli.handle!.address;
  await until(() => cli.records().some((r) => r.msg === 'connected to Home Assistant' && r.tier === 'admin'), 'admin connection');
  await until(() => ha.received.filter((r) => r.message.type === 'auth/current_user').length >= 2, 'a second users-tier check', 5000);
  assert.deepEqual(await probe(address, '/readyz'), { status: 503, body: '' });

  ha.drop.delete('auth/current_user');
  await until(() => cli.records().some((r) => r.msg === 'connected to Home Assistant' && r.tier === 'users'), 'users connection', 5000);
  assert.deepEqual(await probe(address, '/readyz'), { status: 200, body: '' });
  assert.ok(!cli.records().some((r) => r.level === 'error'));
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
