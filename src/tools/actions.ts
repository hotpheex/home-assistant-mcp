import * as z from 'zod';
import { decideConfigRead, decideHelperFlow, decideServiceCall, planServiceCall, type FlowOrigin, type HelperFlow } from '../evaluator.ts';
import { FLOW_ID, FLOW_PATH, HELPER_LISTS, OPTIONS_PATH, type Command } from '../ha.ts';
import { maskSecrets } from '../redaction.ts';
import { mergeTarget, resolveCallTarget } from '../resolver.ts';
import { defineTool, failure, lackingKinds, MASKED, slug, text, ToolFailure, writeResult, type ToolRuntime } from './runtime.ts';

const targetIds = z.union([z.string(), z.array(z.string())]).optional();

interface HaService {
  target?: unknown;
  response?: unknown;
}

export const callService = defineTool({
  operation: 'service_call',
  title: 'Call a service',
  description: [
    'Calls a Home Assistant service, such as light.turn_on, with a `target` in any HA form (entity_id, device_id, area_id, floor_id, label_id, or entity_id "all") and service `data`.',
    'The server expands the target as Home Assistant would, leaves out entities of domains the service does not act on (a switch in an area for light.turn_on), and runs the call only if this Caller may act on every remaining entity; otherwise it refuses the whole call rather than narrowing it.',
    "Target keys inside `data` count as part of the target, and an entity_id named outside the service's domains is refused. A service that takes no target must be called without one.",
    'The result lists the entity_ids acted on, the HA context id and, for a service that responds, its response.',
    'Example: {"domain": "light", "service": "turn_on", "target": {"area_id": "kitchen"}, "data": {"brightness_pct": 40}}.',
  ].join(' '),
  instruction: 'Before calling a service with ha_call_service, check in ha_list_services that it is callable and whether it takes a target.',
  input: z.strictObject({
    domain: slug.describe('Service domain, such as light.'),
    service: slug.describe('Service name, such as turn_on.'),
    target: z
      .strictObject({ entity_id: targetIds, device_id: targetIds, area_id: targetIds, floor_id: targetIds, label_id: targetIds })
      .optional()
      .describe('What the service acts on, in HA target form.'),
    data: z.record(z.string(), z.unknown()).optional().describe('Service data, such as {"brightness_pct": 40}.'),
  }),
  annotations: { readOnlyHint: false, destructiveHint: true },
  async run({ domain, service, target, data = {} }, rt) {
    const name = `${domain}.${service}`;
    const requested = mergeTarget(target, data);
    const names = { service: name, target: requested };
    const denial = failure(
      `Denied: this Caller holds no Grant to call ${name} over ${Object.keys(requested).length ? JSON.stringify(requested) : 'no target'}. Do not retry this call.`,
    );

    const planned = planServiceCall(rt.policy, rt.auth.caller, name);
    if (!planned.plan) {
      rt.audit({ ...names, decision: 'deny', grants: [], denies: planned.denies });
      return denial;
    }
    const { plan } = planned;
    const lookup = (command: Command) => rt.send(command, plan.lookup);
    const description = ((await lookup({ type: 'get_services' })) as Record<string, Record<string, HaService> | undefined>)[domain]?.[service];
    if (!description) throw new ToolFailure(`Service ${name} not found.`);

    const resolved = await resolveCallTarget(lookup, plan, requested, description.target, name);
    if (!resolved.ok) {
      rt.audit({ ...names, decision: 'deny', reason: resolved.reason, ...(resolved.entities !== undefined && { entities: resolved.entities }) });
      throw new ToolFailure(resolved.message);
    }

    const { expansion } = resolved;
    const decision = decideServiceCall(rt.policy, plan, expansion, { domain, service, data, responds: description.response !== undefined });
    if (!decision.allowed) {
      rt.audit({ ...names, decision: 'deny', entities: expansion.entities, grants: decision.grants, denies: decision.denies, uncovered: decision.uncovered });
      return denial;
    }
    const allowed = decision.allowed;
    const result = await rt.writing(
      names,
      decision.grants,
      () => rt.executeWrite<{ context: { id: string }; response?: unknown }>(allowed),
      (r) => ({ context_id: r.context.id }),
      { entities: expansion.entities },
    );
    return writeResult({ entity_ids: expansion.entities, context_id: result.context.id, response: result.response });
  },
});

const FLOW_ARGS = { list: [], start: ['handler'], edit: ['entry_id'], step: ['flow_id', 'input'], abort: ['flow_id'], delete: ['entry_id'] } as const;

async function entryDomain(rt: ToolRuntime, entryId: string): Promise<string> {
  try {
    return (await rt.send<{ config_entry: { domain: string } }>({ type: 'config_entries/get_single', entry_id: entryId })).config_entry.domain;
  } catch (e) {
    if ((e as { code?: unknown }).code === 'not_found') throw new ToolFailure(`No entry ${entryId} exists; list the wizard helpers for their entry ids.`);
    throw e;
  }
}

// HA lists non-user (discovery) flows via `flow/progress` without running them; GET on a flow REST URL re-runs its current step.
async function flowOf(rt: ToolRuntime, flowId: string): Promise<FlowOrigin & { entry_id?: string }> {
  const listed = (await rt.send<{ flow_id: string; handler: string }[]>({ type: 'config_entries/flow/progress' })).find((f) => f.flow_id === flowId);
  if (listed) return { integration: listed.handler, discovered: true };
  const getFlow = (path: string) => rt.rest<{ handler: string } | undefined>({ method: 'GET', path: `${path}/${flowId}` });
  const flow = await getFlow(FLOW_PATH);
  if (flow) return { integration: flow.handler };
  const options = await getFlow(OPTIONS_PATH);
  if (!options) throw new ToolFailure(`No setup or options flow ${flowId} is in progress; start or edit one.`);
  return { integration: await entryDomain(rt, options.handler), entry_id: options.handler };
}

function flowAsked(
  args: { action: HelperFlow['action']; handler?: string; flow_id?: string; entry_id?: string; input?: Record<string, unknown> },
  options: boolean,
): HelperFlow {
  const given = <T>(value: T | undefined): T => {
    if (value === undefined) throw new Error(`${args.action} reached its decision without a validated field`);
    return value;
  };
  switch (args.action) {
    case 'start':
      return { action: 'start', handler: given(args.handler) };
    case 'step':
      return { action: 'step', flow_id: given(args.flow_id), input: given(args.input), options };
    case 'abort':
      return { action: 'abort', flow_id: given(args.flow_id), options };
    case 'edit':
    case 'delete':
      return { action: args.action, entry_id: given(args.entry_id) };
  }
}

export const helperFlow = defineTool({
  operation: 'config_write',
  title: 'Set up, edit or delete a wizard helper',
  description: [
    "Sets up, edits or deletes a wizard helper, such as a template sensor, a light group, a threshold or a switch shown as a light (switch_as_x), by driving Home Assistant's own setup and options forms one step at a time; this is admin-equivalent, because a template switch or button can run any action.",
    '`list` returns the helper integrations Home Assistant offers and the wizard helpers that exist, with their `entry_id`; `start` with a `handler` from that list begins a setup, and `edit` with an `entry_id` begins its options form; `step` with the `flow_id` either returned submits one step\'s `input`, answering a menu with {"next_step_id": "<option>"}; `abort` abandons the flow; `delete` with an `entry_id` removes the helper.',
    "Each step returns Home Assistant's answer as it stands: a `form` with its `data_schema` and any field `errors`, a `menu` with its `menu_options`, an `abort`, or a `create_entry` with the new entry in `result`; input Home Assistant rejects comes back with its field errors, and the same flow can be stepped again.",
    'Only integrations Home Assistant lists as helpers are served, so any other setup, edit or delete is refused, and so is step input that carries **REDACTED** from a read.',
    MASKED,
    'Example: {"action": "step", "flow_id": "9f2c4e1a7b3d4c8e9a1f2b3c4d5e6f70", "input": {"next_step_id": "sensor"}} picks a sensor from the template menu.',
  ].join(' '),
  input: z
    .strictObject({
      action: z.enum(['list', 'start', 'edit', 'step', 'abort', 'delete']).describe('list, start, edit, step, abort or delete.'),
      handler: slug.optional().describe('For start: a helper integration from list, such as template.'),
      flow_id: z.string().regex(FLOW_ID, 'must be the flow_id start or edit returned').optional().describe('For step and abort: the flow_id start or edit returned.'),
      entry_id: z.string().regex(FLOW_ID, 'must be an entry_id list returned').optional().describe("For edit and delete: a wizard helper's entry_id from list."),
      input: z.record(z.string(), z.unknown()).optional().describe('For step: the form\'s fields, or {"next_step_id": "<option>"} for a menu.'),
    })
    .superRefine((args, ctx) => {
      const taken: readonly string[] = FLOW_ARGS[args.action];
      for (const key of ['handler', 'flow_id', 'input', 'entry_id'] as const) {
        if (taken.includes(key) && args[key] === undefined) ctx.addIssue({ code: 'custom', path: [key], message: `is required to ${args.action}` });
        if (!taken.includes(key) && args[key] !== undefined) ctx.addIssue({ code: 'custom', path: [key], message: `is not taken by ${args.action}` });
      }
    }),
  annotations: { readOnlyHint: false, destructiveHint: true },
  kinds: ['helper_entry'],
  reads: ({ action }) => action === 'list',
  decide: ({ action, handler, flow_id, entry_id }, policy, caller) => ({
    ...decideConfigRead(policy, caller, 'helper_entry'),
    lacking: lackingKinds(['helper_entry']),
    request: { kind: 'helper_entry', action, handler, flow_id, entry_id },
  }),
  async run({ action, handler, flow_id, entry_id, input }, rt) {
    const lookup = <T>(path: string) => rt.rest<T>({ method: 'GET', path });
    if (action === 'list') {
      const [handlers, entries] = await Promise.all([
        lookup<string[]>(HELPER_LISTS.handlers),
        lookup<{ entry_id: string; domain: string; title: string }[]>(HELPER_LISTS.entries),
      ]);
      const listed = entries.map(({ entry_id, domain, title }) => ({ entry_id, domain, title }));
      return text(maskSecrets({ handlers: handlers.sort(), entries: listed }));
    }
    const asked = { kind: 'helper_entry', action, flow_id, entry_id };
    rt.refuseRedacted(asked, 'input', input);
    const found =
      handler !== undefined ? { integration: handler } : entry_id !== undefined ? { integration: await entryDomain(rt, entry_id), entry_id } : await flowOf(rt, flow_id!);
    const { integration } = found;
    const flow = flowAsked({ action, handler, flow_id, entry_id, input }, found.entry_id !== undefined);
    const decision = decideHelperFlow(rt.policy, rt.auth.caller, flow, found, await lookup<string[]>(HELPER_LISTS.handlers));
    const audited = { ...asked, handler: integration, entry_id: found.entry_id };
    if (!decision.allowed) {
      const [reason, why] = found.discovered
        ? ['a discovery', `Home Assistant started flow ${flow_id} itself, such as a discovery, so this Caller may not drive it`]
        : ['not a helper integration', `Home Assistant does not list ${integration} as a helper integration, so this Caller may not drive its flows or delete its entries`];
      rt.audit({ ...audited, decision: 'deny', grants: [], reason });
      throw new ToolFailure(`Denied: ${why}. Do not retry this call.`);
    }
    type Answer = { flow_id?: string; type?: string; result?: { entry_id?: string } } | null;
    const allowed = decision.allowed;
    const result = await rt.writing(
      audited,
      decision.grants,
      () => rt.executeWrite<Answer>(allowed),
      (r) => ({
        flow_id: flow_id ?? r?.flow_id,
        entry_id: found.entry_id ?? (r?.type === 'create_entry' ? r.result?.entry_id : undefined),
      }),
    );
    return writeResult(maskSecrets(result));
  },
});
