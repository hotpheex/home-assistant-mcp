import assert from 'node:assert/strict';
import { test } from 'node:test';
import fc from 'fast-check';
import type { Registry } from './fake-ha.ts';
import { connect, fakeHa, newKey, startServer, USERS_TOKEN } from './harness.ts';

// The path property test: generated houses, Policies and calls run through the real server against the fake,
// and a naive oracle, written from ADR 0008 rather than from target.py, judges every call_service HA receives.
const AREAS = ['a1', 'a2'];
const LABELS = ['l1', 'l2'];
const ENTITY_IDS = ['light.one', 'light.two', 'lock.three', 'lock.four', 'switch.five'];
/** Each service's declared `target.entity` domain filter; HA acts on nothing outside it, and null declares none. */
const FILTERS: Record<string, string[] | null> = { 'light.turn_on': ['light'], 'lock.unlock': ['lock'], 'homeassistant.turn_on': null };
const SERVICES = Object.keys(FILTERS);
const admits = (service: string, entityId: string) => FILTERS[service]?.includes(entityId.split('.')[0]!) ?? true;
const PATTERNS = [...SERVICES, 'light.*', 'lock.*'];

const maybe = <T>(values: T[]) => fc.constantFrom<T | null>(null, ...values);
const labels = fc.subarray(LABELS);
const house = fc.record({
  areas: fc.tuple(...AREAS.map((area_id) => fc.record({ area_id: fc.constant(area_id), floor_id: fc.constant(null), labels }))),
  devices: fc.tuple(
    fc.record({ id: fc.constant('d1'), area_id: maybe(AREAS), labels, parent_device_id: fc.constant(null) }),
    fc.record({ id: fc.constant('d2'), area_id: maybe(AREAS), labels, parent_device_id: maybe(['d1']) }),
  ),
  entities: fc.tuple(
    ...ENTITY_IDS.map((entity_id) =>
      fc.record({
        entity_id: fc.constant(entity_id),
        device_id: maybe(['d1', 'd2']),
        area_id: maybe(AREAS),
        labels,
        hidden_by: fc.constantFrom(null, null, null, 'user'),
        disabled_by: fc.constant(null),
        entity_category: maybe(['config' as const, 'diagnostic' as const]),
      }),
    ),
  ),
});
const byDomain = fc.record({ domain: fc.constantFrom('light', 'lock', '*') });
const byArea = fc.record({ area: fc.constantFrom(...AREAS) });
const byLabel = fc.record({ label: fc.constantFrom(...LABELS) });
const ruleOf = (target: fc.Arbitrary<{ domain: string } | { area: string } | { label: string }>, requiredKeys: ('caller' | 'services' | 'targets')[]) =>
  fc.record(
    { caller: fc.constant('agent'), services: fc.uniqueArray(fc.constantFrom(...PATTERNS), { minLength: 1, maxLength: 2 }), targets: fc.array(target, { minLength: 1, maxLength: 2 }) },
    { requiredKeys },
  );
const rule = ruleOf(fc.oneof(byDomain, byArea, byLabel), ['caller', 'services']);
// A domain Deny or one withholding entirely hides how area and label Denies expand, so those are drawn most often.
const deny = fc.oneof({ arbitrary: rule, weight: 1 }, { arbitrary: ruleOf(fc.oneof(byArea, byLabel), ['caller', 'services', 'targets']), weight: 3 });
const callTarget = fc.oneof(
  fc.record({ entity_id: fc.oneof(fc.constant('all'), fc.subarray(ENTITY_IDS, { minLength: 1 })) }),
  fc.record({ area_id: fc.constantFrom(...AREAS) }),
  fc.record({ label_id: fc.constantFrom(...LABELS) }),
  fc.record({ device_id: fc.constantFrom('d1', 'd2') }),
);
const call = fc.record({ service: fc.constantFrom(...SERVICES), target: callTarget, inData: fc.boolean() });
const scenario = fc.record({ house, grants: fc.array(rule, { minLength: 1, maxLength: 3 }), denies: fc.array(deny, { minLength: 1, maxLength: 2 }), calls: fc.array(call, { minLength: 3, maxLength: 8 }) });

type House = Registry;
type Rule = { services: string[]; targets?: ({ domain: string } | { area: string } | { label: string })[] };
type Entity = Registry['entities'][number];

const delegating = (s: string) => s.startsWith('homeassistant.') || s === 'scene.apply';
const names = (r: Rule, s: string, deny: boolean) => r.services.some((p) => p === s || (p.endsWith('.*') && s.startsWith(p.slice(0, -1)) && (deny || !delegating(s))));

/** In an area: its own area, or no area and its device's (or parent device's) area. Hidden never; config only for a Deny. */
function inArea(h: House, e: Entity, area: string, primary: boolean) {
  if (e.hidden_by !== null || (primary && e.entity_category !== null)) return false;
  if (e.area_id !== null) return e.area_id === area;
  const device = h.devices.find((d) => d.id === e.device_id);
  const parent = h.devices.find((d) => d.id === device?.parent_device_id);
  return (device?.area_id ?? parent?.area_id ?? null) === area;
}

/** Reached by a label: labelled directly, through a labelled device or its parent, or through a labelled area. */
function hasLabel(h: House, e: Entity, label: string, primary: boolean) {
  if (e.hidden_by !== null) return false;
  if (e.labels.includes(label)) return true;
  const device = h.devices.find((d) => d.id === e.device_id);
  const parent = h.devices.find((d) => d.id === device?.parent_device_id);
  const viaDevice = (device?.labels.includes(label) ?? false) || (parent?.labels.includes(label) ?? false);
  if (viaDevice && !(primary && e.entity_category !== null)) return true;
  return h.areas.some((a) => a.labels.includes(label) && inArea(h, e, a.area_id, primary));
}

function reaches(h: House, r: Rule, entityId: string, primary: boolean) {
  const e = h.entities.find((x) => x.entity_id === entityId);
  return (r.targets ?? []).some((t) => {
    if ('domain' in t) return t.domain === '*' || entityId.startsWith(`${t.domain}.`);
    if (e === undefined) return false;
    return 'area' in t ? inArea(h, e, t.area, primary) : hasLabel(h, e, t.label, primary);
  });
}

test('property: every service call HA receives acts only on entities a Grant covers and no Deny reaches', async (t) => {
  const agent = newKey();
  let forwarded = 0;
  await fc.assert(
    fc.asyncProperty(scenario, async ({ house, grants, denies, calls }) => {
      const registry: House = { ...house, areas: [...house.areas], devices: [...house.devices], entities: [...house.entities], floors: [], labels: LABELS.map((label_id) => ({ label_id })) };
      const services = Object.fromEntries(
        Object.entries(FILTERS).map(([s, domain]) => {
          const [d = '', n = ''] = s.split('.');
          return [d, { [n]: { target: { entity: [domain ? { domain } : {}] } } }] as const;
        }),
      );
      const ha = await fakeHa(t, { ...registry, services, states: registry.entities.map((e) => ({ entity_id: e.entity_id, state: 'on', attributes: {} })) });
      const policy = JSON.stringify({ version: 1, callers: { agent: { keys: [{ sha256: agent.sha256 }] } }, grants, denies });
      const server = await startServer(t, policy, ha);
      const client = await connect(t, server.url, agent.key, 'modern');

      for (const { service, target, inData } of calls) {
        const before = ha.received.length;
        const [domain, name] = service.split('.');
        await client.callTool({ name: 'ha_call_service', arguments: { domain, service: name, ...(inData ? { data: target } : { target }) } });
        const sent = ha.received.slice(before);
        const refusedAtPlan = !grants.some((g) => names(g, service, false)) || denies.some((d) => names(d, service, true) && d.targets === undefined);
        if (refusedAtPlan) assert.deepEqual(sent, []);
        const forwardedCalls = sent.filter((r) => r.message.type === 'call_service');
        const named = 'entity_id' in target && Array.isArray(target.entity_id) ? target.entity_id : [];
        if (named.some((e) => !admits(service, e))) assert.deepEqual(forwardedCalls, [], 'an entity_id named outside the service domains was left out');
        for (const { message } of forwardedCalls) {
          assert.equal(`${String(message.domain)}.${String(message.service)}`, service);
          forwarded++;
          for (const e of (message.target as { entity_id: string[] }).entity_id) {
            assert.ok(admits(service, e), `${e} is outside the domains ${service} acts on`);
            assert.ok(grants.some((g) => names(g, service, false) && reaches(registry, g, e, true)), `${e} is not covered by a Grant`);
            assert.ok(!denies.some((d) => names(d, service, true) && reaches(registry, d, e, false)), `${e} is under a Deny`);
          }
        }
      }
      assert.ok(ha.received.every((r) => r.token === USERS_TOKEN));
    }),
    { numRuns: 150 },
  );
  assert.ok(forwarded > 0, 'no generated call was ever allowed, so the property checked nothing');
});
