import assert from 'node:assert/strict';
import { test } from 'node:test';
import fc from 'fast-check';
import { decideConfigRead, decideConfigWrite, decideHelperFlow, decideServiceCall, planServiceCall, type Expansion, type HelperFlow, type Selectors } from '../src/evaluator.ts';
import { CONFIG_KINDS, parsePolicy, type Policy } from '../src/policy.ts';

const HASH = 'a'.repeat(64);
const policyOf = (rules: string) => parsePolicy(`version: 1\ncallers:\n  agent:\n    keys: [{ sha256: ${HASH} }]\n${rules}`);

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

test('an allowed call carries exactly the checked entity_id list, sorted, and no target keys in its data', () => {
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
  { caller: fc.constantFrom('agent', 'other'), services: fc.uniqueArray(fc.constantFrom(...PATTERNS), { minLength: 1, maxLength: 3 }), targets: fc.array(target, { minLength: 1, maxLength: 3 }) },
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
  if (entity === undefined) return true;
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

test('property: an entity_name write is decided by its own Grant only, and its command carries only name, icon and aliases', () => {
  const grant = fc.record({ caller: fc.constantFrom('agent', 'other'), config_write: fc.constantFrom(...CONFIG_KINDS) });
  const config = fc.dictionary(fc.constantFrom('name', 'icon', 'aliases', 'area_id', 'labels', 'hidden_by', 'disabled_by', 'new_entity_id'), fc.string());
  fc.assert(
    fc.property(fc.array(grant, { maxLength: 6 }), config, (grants, config) => {
      const policy = { version: 1, callers: { agent: { keys: [] }, other: { keys: [] } }, grants, denies: [], sha256: '' } as unknown as Policy;
      const { allowed } = decideConfigWrite(policy, 'agent', { kind: 'entity_name', action: 'update', id: 'lock.garage', config });
      assert.equal(allowed !== undefined, grants.some((g) => g.caller === 'agent' && g.config_write === 'entity_name'));
      if (allowed?.write.via !== 'websocket') return;
      const { type, entity_id, ...fields } = allowed.write.command;
      assert.deepEqual([type, entity_id], ['config/entity_registry/update', 'lock.garage']);
      assert.deepEqual(Object.keys(fields).sort(), Object.keys(config).filter((k) => ['name', 'icon', 'aliases'].includes(k)).sort());
    }),
  );
});

const writeGrants = fc.array(fc.record({ caller: fc.constantFrom('agent', 'other'), config_write: fc.constantFrom(...CONFIG_KINDS) }), { maxLength: 4 });
const flow: fc.Arbitrary<HelperFlow> = fc.oneof(
  fc.record({ action: fc.constant('start' as const), handler: fc.constantFrom('template', 'hue') }),
  fc.record({ action: fc.constant('step' as const), flow_id: fc.oneof(fc.constant('9f2c4e1a7b3d4c8e'), fc.constant('../../automation/config/x'), fc.string()), input: fc.constant({}) }),
  fc.record({ action: fc.constant('abort' as const), flow_id: fc.oneof(fc.constant('9f2c4e1a7b3d4c8e'), fc.constant('../../automation/config/x'), fc.string()) }),
);
const holds = (grants: { caller: string; config_write: string }[], kind: string) => grants.some((g) => g.caller === 'agent' && g.config_write === kind);

test('property: only helper_entry allows a wizard-helper flow, never helper, and helper_entry allows no helper write', () => {
  fc.assert(
    fc.property(writeGrants, flow, (grants, f) => {
      const policy = asPolicy(grants as unknown as Rule[], []);
      const integration = f.action === 'start' ? f.handler : 'template';
      const allowed = decideHelperFlow(policy, 'agent', f, integration, ['template']).allowed !== undefined;
      const helper = decideConfigWrite(policy, 'agent', { kind: 'helper', action: 'create', id: 'input_boolean.x', config: {} }).allowed !== undefined;
      const entry = decideConfigWrite(policy, 'agent', { kind: 'helper_entry', action: 'create', id: 'x', config: {} }).allowed !== undefined;
      return (!allowed || holds(grants, 'helper_entry')) && helper === holds(grants, 'helper') && !entry;
    }),
  );
});

test('property: a zone write and zone config read need a zone Grant, which writes nothing but zones', () => {
  const kinds = fc.uniqueArray(fc.constantFrom(...CONFIG_KINDS));
  fc.assert(
    fc.property(kinds, fc.constantFrom(...CONFIG_KINDS), (held, kind) => {
      const policy = { grants: held.map((config_write) => ({ caller: 'agent', config_write })), denies: [] } as unknown as Policy;
      const write = decideConfigWrite(policy, 'agent', { kind, action: 'delete', id: 'office' }).allowed?.write;
      const command = write?.via === 'websocket' ? write.command.type : undefined;
      // A wizard helper is written only through its flow.
      assert.equal(write !== undefined, held.includes(kind) && kind !== 'helper_entry');
      assert.equal(command?.startsWith('zone/') ?? false, kind === 'zone' && held.includes('zone'));
      if (kind === 'zone') assert.equal(decideConfigRead(policy, 'agent', kind).allowed !== undefined, held.includes('zone'));
    }),
  );
});

test('property: a dashboard write or config read is decided by a dashboard Grant alone, and is a lovelace WebSocket command', () => {
  const grant = fc.record({ caller: fc.constantFrom('agent', 'other'), config_write: fc.constantFrom(...CONFIG_KINDS) });
  const write = fc.record({ action: fc.constantFrom('create', 'update', 'delete' as const), id: fc.constantFrom('lovelace', 'kitchen-wall', 'map') });
  fc.assert(
    fc.property(fc.array(grant), write, fc.constantFrom(...CONFIG_KINDS), (grants, { action, id }, other) => {
      const policy = asPolicy(grants as unknown as Rule[], []);
      const holds = (kind: string) => grants.some((g) => g.caller === 'agent' && g.config_write === kind);
      const { allowed } = decideConfigWrite(policy, 'agent', { kind: 'dashboard', action, id, config: action === 'delete' ? undefined : { title: 'x' } });
      assert.equal(allowed !== undefined, holds('dashboard'));
      assert.equal(decideConfigRead(policy, 'agent', 'dashboard').allowed !== undefined, holds('dashboard'));
      if (other !== 'dashboard' && !holds(other)) assert.equal(decideConfigWrite(policy, 'agent', { kind: other, action: 'delete', id: 'x' }).allowed, undefined);
      if (allowed?.write.via !== 'websocket') return allowed === undefined;
      return /^lovelace\/(dashboards\/(create|delete)|config\/save)$/.test(allowed.write.command.type);
    }),
  );
});

test("property: a flow is allowed only for an integration in HA's helper list, and only within HA's flow API", () => {
  fc.assert(
    fc.property(flow, fc.constantFrom('template', 'hue'), (f, integration) => {
      const policy = asPolicy([{ caller: 'agent', config_write: 'helper_entry' }] as unknown as Rule[], []);
      const { allowed } = decideHelperFlow(policy, 'agent', f, integration, ['template']);
      if (allowed?.write.via !== 'rest') return allowed === undefined;
      const { path } = allowed.write.request;
      return integration === 'template' && new URL(path, 'http://ha').pathname.startsWith('/api/config/config_entries/flow') && !path.includes('..');
    }),
  );
});
