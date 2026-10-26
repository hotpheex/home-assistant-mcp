import assert from 'node:assert/strict';
import { test } from 'node:test';
import fc from 'fast-check';
import { decideServiceCall, planServiceCall, type Expansion, type Selectors } from '../src/evaluator.ts';
import { parsePolicy, type Policy } from '../src/policy.ts';

const HASH = 'a'.repeat(64);
const policyOf = (rules: string) => parsePolicy(`version: 1\ncallers:\n  agent:\n    keys: [{ sha256: ${HASH} }]\n${rules}`);

test('plan refuses a service no Grant of the Caller names, and a delegating service a wildcard names', () => {
  const policy = policyOf(`grants:
  - caller: agent
    services: [lock.unlock, scene.*]
  - caller: agent
    services: [light.*]
    targets: [{ area: kitchen }]
`);
  assert.equal(planServiceCall(policy, 'agent', 'light.toggle').plan?.grants.join(), '1');
  assert.equal(planServiceCall(policy, 'agent', 'switch.turn_on').plan, undefined);
  assert.equal(planServiceCall(policy, 'agent', 'scene.apply').plan, undefined);
  assert.equal(planServiceCall(policy, 'other', 'lock.unlock').plan, undefined);
});

const tablePolicy = policyOf(`grants:
  - caller: agent
    services: [light.turn_on, shell_command.backup]
    targets: [{ domain: light }, { area: kitchen }]
  - caller: agent
    services: [light.*]
    targets: [{ label: night }]
denies:
  - caller: agent
    services: [light.turn_on]
    targets: [{ area: garage }, { domain: switch }]
  - caller: agent
    services: [shell_command.*]
    targets: [{ label: night }]
`);
const call = { domain: 'light', service: 'turn_on', data: { brightness: 9, entity_id: 'lock.door', area_id: 'x' }, responds: false };

const table: { name: string; service?: string; expansion: Expansion; decision: Record<string, unknown> }[] = [
  {
    name: 'a domain selector covers by entity_id prefix',
    expansion: { targeted: true, entities: ['light.a', 'light.b'], grantEntities: [], denyEntities: [] },
    decision: { allowed: true, grants: [0], denies: [], uncovered: [] },
  },
  {
    name: 'area and label selectors cover what HA expanded them to',
    expansion: { targeted: true, entities: ['fan.k', 'cover.n'], grantEntities: ['fan.k', 'cover.n'], denyEntities: [] },
    decision: { allowed: true, grants: [0, 1], denies: [], uncovered: [] },
  },
  {
    name: 'one uncovered entity refuses the whole call',
    expansion: { targeted: true, entities: ['light.a', 'lock.door'], grantEntities: [], denyEntities: [] },
    decision: { allowed: false, grants: [], denies: [], uncovered: ['lock.door'] },
  },
  {
    name: 'a Deny wins over a covering Grant, by HA expansion or by domain',
    expansion: { targeted: true, entities: ['light.g', 'switch.k'], grantEntities: ['switch.k'], denyEntities: ['light.g'] },
    decision: { allowed: false, grants: [], denies: [0], uncovered: [] },
  },
  {
    name: 'a targetless service is checked by name alone',
    service: 'shell_command.backup',
    expansion: { targeted: false, entities: [], grantEntities: [], denyEntities: [] },
    decision: { allowed: false, grants: [], denies: [1], uncovered: [] },
  },
];

for (const { name, service = 'light.turn_on', expansion, decision } of table) {
  test(`decide: ${name}`, () => {
    const { plan } = planServiceCall(tablePolicy, 'agent', service);
    assert.ok(plan);
    const result = decideServiceCall(tablePolicy, plan, expansion, call);
    assert.deepEqual(
      { allowed: result.allowed !== undefined, grants: result.grants, denies: result.denies, uncovered: result.uncovered },
      decision,
    );
  });
}

test('an allowed call carries exactly the checked entity_id list, and no target keys in its data', () => {
  const { plan } = planServiceCall(tablePolicy, 'agent', 'light.turn_on');
  assert.ok(plan);
  const expansion = { targeted: true, entities: ['light.b', 'light.a'], grantEntities: [], denyEntities: [] };
  assert.deepEqual(decideServiceCall(tablePolicy, plan, expansion, { ...call, responds: true }).allowed?.write.command, {
    type: 'call_service',
    domain: 'light',
    service: 'turn_on',
    target: { entity_id: ['light.a', 'light.b'] },
    service_data: { brightness: 9 },
    return_response: true,
  });
  const policy = policyOf(`grants:\n  - caller: agent\n    services: [shell_command.backup]\n`);
  const targetless = planServiceCall(policy, 'agent', 'shell_command.backup').plan;
  assert.ok(targetless);
  const none = { targeted: false, entities: [], grantEntities: [], denyEntities: [] };
  assert.deepEqual(decideServiceCall(policy, targetless, none, { ...call, domain: 'shell_command', service: 'backup' }).allowed?.write.command, {
    type: 'call_service',
    domain: 'shell_command',
    service: 'backup',
    service_data: { brightness: 9 },
  });
});

// Properties over generated Policies. HA's expansion is modelled as a fixed map from selector to entities,
// wider for Denies, as primary_entities_only=false is.
const ENTITIES = ['light.a', 'light.b', 'lock.c', 'switch.d', 'scene.e'];
const SERVICES = ['light.turn_on', 'lock.unlock', 'switch.toggle', 'scene.apply', 'homeassistant.turn_off'];
const PATTERNS = [...SERVICES, 'light.*', 'lock.*', 'scene.*'];
const SELECTORS = ['area:a1', 'area:a2', 'label:l1', 'label:l2'];

const target = fc.oneof(
  fc.record({ domain: fc.constantFrom('light', 'lock', 'switch', '*') }),
  fc.record({ area: fc.constantFrom('a1', 'a2') }),
  fc.record({ label: fc.constantFrom('l1', 'l2') }),
);
const rule = fc.record(
  { caller: fc.constantFrom('agent', 'other'), services: fc.uniqueArray(fc.constantFrom(...PATTERNS), { minLength: 1, maxLength: 3 }), targets: fc.array(target, { maxLength: 3 }) },
  { requiredKeys: ['caller', 'services'] },
);
const world = fc.record(Object.fromEntries(SELECTORS.map((s) => [s, fc.subarray(ENTITIES)])));
const scenario = fc.record({
  grants: fc.array(rule, { maxLength: 4 }),
  denies: fc.array(rule, { maxLength: 2 }),
  extra: rule,
  service: fc.constantFrom(...SERVICES),
  entities: fc.subarray(ENTITIES, { minLength: 1 }),
  targeted: fc.boolean(),
  grantWorld: world,
  denyExtra: world,
});
type Scenario = typeof scenario extends fc.Arbitrary<infer S> ? S : never;
type Rule = Scenario['extra'];

const asPolicy = (grants: Rule[], denies: Rule[]) =>
  ({ version: 1, callers: { agent: { keys: [] }, other: { keys: [] } }, grants, denies, sha256: '' }) as unknown as Policy;
const denyWorld = (s: Scenario) => Object.fromEntries(SELECTORS.map((k) => [k, [...s.grantWorld[k]!, ...s.denyExtra[k]!]]));
const expand = (w: Record<string, string[]>, sel: Selectors) => [...sel.area_id.map((a) => `area:${a}`), ...sel.label_id.map((l) => `label:${l}`)].flatMap((k) => w[k] ?? []);

function decide(s: Scenario, grants = s.grants) {
  const policy = asPolicy(grants, s.denies);
  const { plan } = planServiceCall(policy, 'agent', s.service);
  if (!plan) return false;
  const expansion = {
    targeted: s.targeted,
    entities: s.targeted ? s.entities : [],
    grantEntities: expand(s.grantWorld, plan.grantSelectors),
    denyEntities: expand(denyWorld(s), plan.denySelectors),
  };
  const [domain = '', service = ''] = s.service.split('.');
  return decideServiceCall(policy, plan, expansion, { domain, service, data: {}, responds: false }).allowed !== undefined;
}

/** The naive oracle: does this rule reach this entity of this call, read straight from ADR 0008 and the spec? */
function reaches(r: Rule, s: Scenario, entity: string | undefined, w: Record<string, string[]>, deny: boolean) {
  if (r.caller !== 'agent') return false;
  const delegating = s.service === 'scene.apply' || s.service.startsWith('homeassistant.');
  const named = r.services.some((p) => p === s.service || (p.endsWith('.*') && s.service.startsWith(p.slice(0, -1)) && (deny || !delegating)));
  if (!named) return false;
  if (entity === undefined) return true; // a targetless service: by name alone
  if (deny && r.targets === undefined) return true;
  return (r.targets ?? []).some((t) =>
    'domain' in t ? t.domain === '*' || entity.startsWith(`${t.domain}.`) : (w['area' in t ? `area:${t.area}` : `label:${t.label}`] ?? []).includes(entity),
  );
}
const callEntities = (s: Scenario) => (s.targeted ? s.entities : [undefined]);

test('property: default deny, a Caller with no Grant is refused every service', () => {
  fc.assert(fc.property(scenario, (s) => !decide(s, [])));
});

test('property: a Deny always wins', () => {
  fc.assert(
    fc.property(scenario, (s) => {
      const denied = s.denies.some((d) => callEntities(s).some((e) => reaches(d, s, e, denyWorld(s), true)));
      return !denied || !decide(s);
    }),
  );
});

test('property: an allowed call has every entity covered by a Grant, so one uncovered entity refuses it', () => {
  fc.assert(
    fc.property(scenario, (s) => {
      const covered = callEntities(s).every((e) => s.grants.some((g) => reaches(g, s, e, s.grantWorld, false)));
      return covered || !decide(s);
    }),
  );
});

test('property: adding a Grant never turns an allow into a deny', () => {
  fc.assert(fc.property(scenario, (s) => !decide(s) || decide(s, [...s.grants, s.extra])));
});
