import { ProtocolError, ProtocolErrorCode, Server, type CallToolResult, type Tool } from '@modelcontextprotocol/server';
import * as z from 'zod';
import pkg from '../package.json' with { type: 'json' };
import type { Authenticated } from './auth.ts';
import { callable, decideRead, decideServiceCall, grantsFor, planServiceCall, type Allowed, type Operation } from './evaluator.ts';
import { HaError, HaUnavailable, OutcomeUnknown, type Command, type Gate } from './gate.ts';
import type { Audit } from './log.ts';
import type { Policy } from './policy.ts';
import { expandAll, extract, mergeTarget } from './resolver.ts';

/** The Operation kind a Caller must hold to see and call each tool. */
export const TOOL_KIND = {
  ha_get_states: 'plain_read',
  ha_call_service: 'service_call',
  ha_list_services: 'plain_read',
} as const satisfies Record<string, Operation>;
export type ToolName = keyof typeof TOOL_KIND;

const OPERATION_NAME: Record<Operation, string> = {
  plain_read: 'plain read',
  config_read: 'config read',
  service_call: 'service calls',
  config_write: 'config writes',
};

interface Context {
  policy: Policy;
  caller: Authenticated;
  gate: Gate;
  audit: Audit;
}

interface ToolSpec<Input extends z.ZodType> {
  title: string;
  description: string;
  input: Input;
  annotations: { readOnlyHint: boolean; destructiveHint: boolean };
  run(args: z.output<Input>, ctx: Context): Promise<CallToolResult>;
}

const page = {
  limit: z.number().int().min(1).max(500).default(50).describe('Page size, at most 500.'),
  offset: z.number().int().min(0).default(0).describe('Entries to skip.'),
};

const text = (value: unknown): CallToolResult => ({ content: [{ type: 'text', text: JSON.stringify(value) }] });
const failure = (message: string): CallToolResult => ({ isError: true, content: [{ type: 'text', text: message }] });

/** About 80 kB keeps a result under Claude Code's default MCP output limit. */
const RESPONSE_CAP = 80_000;

/** A write has already run, so an oversize response is cut with a visible marker rather than refused. */
function writeResult(value: unknown): CallToolResult {
  const full = Buffer.from(JSON.stringify(value));
  if (full.length <= RESPONSE_CAP) return text(value);
  const marker = `\n[truncated: the response was ${full.length} bytes, over the ${RESPONSE_CAP}-byte cap; the call ran]`;
  const kept = full.subarray(0, RESPONSE_CAP - Buffer.byteLength(marker)).toString().replace(/\uFFFD$/, '');
  return { content: [{ type: 'text', text: kept + marker }] };
}

/** A failure the Caller can act on, returned as an isError result. */
class ToolFailure extends Error {}

/** Sends a read the evaluator allowed. */
async function read<T>(ctx: Context, allowed: Allowed | undefined, command: { type: string }): Promise<T> {
  if (!allowed) throw new Error('read sent without an Allowed');
  try {
    return (await ctx.gate.send(allowed, command)) as T;
  } catch (e) {
    if (e instanceof HaUnavailable) throw new ToolFailure('HA unavailable: nothing was sent to Home Assistant. Try again later.');
    if (e instanceof OutcomeUnknown) {
      throw new ToolFailure('Outcome unknown: the connection to Home Assistant dropped after the call was sent. Check state before retrying.');
    }
    if (e instanceof HaError) throw new ToolFailure(`Home Assistant error: ${e.message}`);
    throw e;
  }
}

/** Sends the exact write the evaluator allowed. */
const write = <T>(ctx: Context, allowed: Allowed) => read<T>(ctx, allowed, allowed.command!);

interface HaState {
  entity_id: string;
  state: string;
  attributes: { friendly_name?: string };
}

/** Infers each tool's arguments from its input schema, then erases them for the shared table. */
const defineTool = <Input extends z.ZodType>(spec: ToolSpec<Input>) => spec as unknown as ToolSpec<z.ZodType>;

const getStates = defineTool({
  title: 'Get entity states',
  description: [
    'Lists the current state of Home Assistant entities, sorted by entity_id, with each entity_id, friendly name and state.',
    'Filter by `domain` (such as `light`) and by `query`, a case-insensitive substring of the entity_id or friendly name.',
    "Filter by `area` or `label` id: these match what a Home Assistant service call targeting that area or label acts on.",
    'Results come in pages: `limit` (default 50, at most 500) and `offset` pick the page, and the response gives `total` and `has_more`.',
    'Example: {"domain": "light", "query": "kitchen"} lists the kitchen lights.',
  ].join(' '),
  input: z.strictObject({
    query: z.string().min(1).optional().describe('Case-insensitive substring of the entity_id or friendly name.'),
    domain: z.string().regex(/^[a-z0-9_]+$/).optional().describe('Entity domain, such as light or sensor.'),
    area: z.string().min(1).optional().describe('Area id, such as living_room.'),
    label: z.string().min(1).optional().describe('Label id.'),
    ...page,
  }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run(args, ctx) {
    const allowed = decideRead(ctx.policy, ctx.caller.caller, 'plain_read').allowed;
    const states = await read<HaState[]>(ctx, allowed, { type: 'get_states' });
    const lookup = (command: Command) => read(ctx, allowed, command);
    const within = async (key: 'area_id' | 'label_id', id: string | undefined) => (id === undefined ? undefined : new Set(await extract(lookup, { [key]: [id] })));
    const inArea = await within('area_id', args.area);
    const labelled = await within('label_id', args.label);
    const query = args.query?.toLowerCase();
    const matches = states
      .filter((s) => args.domain === undefined || s.entity_id.startsWith(`${args.domain}.`))
      .filter((s) => (inArea?.has(s.entity_id) ?? true) && (labelled?.has(s.entity_id) ?? true))
      .filter((s) => query === undefined || [s.entity_id, s.attributes.friendly_name ?? ''].some((v) => v.toLowerCase().includes(query)))
      .sort((a, b) => a.entity_id.localeCompare(b.entity_id));
    return text({
      total: matches.length,
      offset: args.offset,
      has_more: args.offset + args.limit < matches.length,
      states: matches
        .slice(args.offset, args.offset + args.limit)
        .map((s) => ({ entity_id: s.entity_id, name: s.attributes.friendly_name, state: s.state })),
    });
  },
});

const targetIds = z.union([z.string(), z.array(z.string())]).optional();

interface HaService {
  name?: string;
  description?: string;
  fields?: Record<string, unknown>;
  target?: unknown;
  response?: unknown;
}

const listServices = defineTool({
  title: 'List services',
  description: [
    'Lists every service Home Assistant offers, sorted by name, each with its fields, whether it takes a target, whether it returns a response, and whether this Caller may call it (`callable`).',
    'A service marked callable may still be refused for a particular target that this Caller may not act on.',
    'Filter by `domain` (such as `light`).',
    'Results come in pages: `limit` (default 50, at most 500) and `offset` pick the page, and the response gives `total` and `has_more`.',
    'Example: {"domain": "light"} lists the light services.',
  ].join(' '),
  input: z.strictObject({
    domain: z.string().regex(/^[a-z0-9_]+$/).optional().describe('Service domain, such as light.'),
    ...page,
  }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run(args, ctx) {
    const all = await read<Record<string, Record<string, HaService>>>(ctx, decideRead(ctx.policy, ctx.caller.caller, 'plain_read').allowed, { type: 'get_services' });
    const services = Object.entries(all)
      .filter(([domain]) => args.domain === undefined || domain === args.domain)
      .flatMap(([domain, byName]) => Object.entries(byName).map(([name, d]) => ({ service: `${domain}.${name}`, d })))
      .sort((a, b) => a.service.localeCompare(b.service));
    return text({
      total: services.length,
      offset: args.offset,
      has_more: args.offset + args.limit < services.length,
      services: services.slice(args.offset, args.offset + args.limit).map(({ service, d }) => ({
        service,
        ...(d.name === undefined ? {} : { name: d.name }),
        ...(d.description === undefined ? {} : { description: d.description }),
        fields: d.fields ?? {},
        target: d.target !== undefined,
        response: d.response !== undefined,
        callable: callable(ctx.policy, ctx.caller.caller, service, d.target !== undefined),
      })),
    });
  },
});

const callService = defineTool({
  title: 'Call a service',
  description: [
    'Calls a Home Assistant service, such as light.turn_on, with a `target` in any HA form (entity_id, device_id, area_id, floor_id, label_id, or entity_id "all") and service `data`.',
    'The server expands the target as Home Assistant would, and runs the call only if this Caller may act on every entity it reaches; otherwise it refuses the whole call rather than narrowing it.',
    'Target keys inside `data` count as part of the target. A service that takes no target must be called without one.',
    'The result lists the entity_ids acted on, the HA context id and, for a service that responds, its response.',
    'Example: {"domain": "light", "service": "turn_on", "target": {"area_id": "kitchen"}, "data": {"brightness_pct": 40}}.',
  ].join(' '),
  input: z.strictObject({
    domain: z.string().regex(/^[a-z0-9_]+$/).describe('Service domain, such as light.'),
    service: z.string().regex(/^[a-z0-9_]+$/).describe('Service name, such as turn_on.'),
    target: z
      .strictObject({ entity_id: targetIds, device_id: targetIds, area_id: targetIds, floor_id: targetIds, label_id: targetIds })
      .optional()
      .describe('What the service acts on, in HA target form.'),
    data: z.record(z.string(), z.unknown()).optional().describe('Service data, such as {"brightness_pct": 40}.'),
  }),
  annotations: { readOnlyHint: false, destructiveHint: true },
  async run({ domain, service, target, data = {} }, ctx) {
    const name = `${domain}.${service}`;
    const requested = mergeTarget(target, data);
    const audit = (record: Record<string, unknown>) =>
      ctx.audit({ caller: ctx.caller.caller, key_hash_prefix: ctx.caller.keyHashPrefix, operation: 'service_call', tool: 'ha_call_service', service: name, target: requested, ...record });
    const denial = failure(`Denied: this Caller holds no Grant to call ${name} over ${Object.keys(requested).length ? JSON.stringify(requested) : 'no target'}. Do not retry this call.`);

    const planned = planServiceCall(ctx.policy, ctx.caller.caller, name);
    if (!planned.plan) {
      audit({ decision: 'deny', grants: [], denies: planned.denies });
      return denial;
    }
    const { plan } = planned;
    const lookup = (command: Command) => read(ctx, plan.lookup, command);
    const description = ((await lookup({ type: 'get_services' })) as Record<string, Record<string, HaService> | undefined>)[domain]?.[service];
    if (!description) throw new ToolFailure(`Service ${name} not found.`);
    const targeted = description.target !== undefined;
    const hasTarget = Object.keys(requested).length > 0;
    if (targeted && !hasTarget) throw new ToolFailure(`${name}: this service needs a target.`);
    if (!targeted && hasTarget) throw new ToolFailure(`${name}: this service takes no target.`);

    const expansion = { targeted, entities: [] as string[], grantEntities: [] as string[], denyEntities: [] as string[] };
    if (targeted) {
      expansion.entities = await extract(lookup, await expandAll(lookup, requested, name));
      if (expansion.entities.length === 0) throw new ToolFailure(`${name}: target matches no entity.`);
      expansion.grantEntities = await extract(lookup, plan.grantSelectors);
      expansion.denyEntities = await extract(lookup, plan.denySelectors, false);
    }
    const decision = decideServiceCall(ctx.policy, plan, expansion, { domain, service, data, responds: description.response !== undefined });
    const { grants, uncovered } = decision;
    if (!decision.allowed) {
      audit({ decision: 'deny', entities: expansion.entities, grants, denies: decision.denies, uncovered });
      return denial;
    }
    const result = await write<{ context: { id: string }; response?: unknown }>(ctx, decision.allowed);
    audit({ decision: 'allow', entities: expansion.entities, grants, context_id: result.context.id });
    return writeResult({ entity_ids: expansion.entities, context_id: result.context.id, ...('response' in result ? { response: result.response } : {}) });
  },
});

const TOOLS: Record<ToolName, ToolSpec<z.ZodType>> = { ha_get_states: getStates, ha_call_service: callService, ha_list_services: listServices };

/** Built once, so each tool's definition is identical for every Caller. */
const DEFINITIONS = Object.fromEntries(
  Object.entries(TOOLS).map(([name, t]) => [
    name,
    { name, title: t.title, description: t.description, inputSchema: z.toJSONSchema(t.input, { io: 'input' }), annotations: t.annotations } as Tool,
  ]),
) as Record<ToolName, Tool>;

const isTool = (name: string): name is ToolName => Object.hasOwn(TOOLS, name);

/**
 * One server per request, listing only the tools whose kind the Caller holds. A hidden tool called
 * directly is refused and audited before its input is read, so nothing reaches HA.
 */
export function buildServer(policy: Policy, gate: Gate, audit: Audit, caller: Authenticated): Server {
  const ctx: Context = { policy, caller, gate, audit };
  const holds = (name: ToolName) => grantsFor(policy, caller.caller, TOOL_KIND[name]).length > 0;
  const server = new Server(
    { name: pkg.name, version: pkg.version },
    { capabilities: { tools: {} }, cacheHints: { 'tools/list': { cacheScope: 'private', ttlMs: 0 } } },
  );
  server.setRequestHandler('tools/list', () => ({
    tools: Object.values(DEFINITIONS).filter((d) => holds(d.name as ToolName)),
  }));
  server.setRequestHandler('tools/call', async ({ params }) => {
    const { name } = params;
    if (!isTool(name)) throw new ProtocolError(ProtocolErrorCode.InvalidParams, `Tool ${name} not found`);
    const operation = TOOL_KIND[name];
    if (!holds(name)) {
      audit({ caller: caller.caller, key_hash_prefix: caller.keyHashPrefix, operation, tool: name, decision: 'deny', grants: [] });
      return failure(`Denied: this Caller holds no Grant for ${OPERATION_NAME[operation]}. Do not retry this call.`);
    }
    const tool = TOOLS[name];
    const args = tool.input.safeParse(params.arguments ?? {});
    if (!args.success) {
      return failure(`Input validation error: ${args.error.issues.map((i) => `${i.path.join('.') || '(arguments)'}: ${i.message}`).join('; ')}`);
    }
    try {
      return server.projectCallToolResult(await tool.run(args.data, ctx), undefined);
    } catch (e) {
      if (e instanceof ToolFailure) return failure(e.message);
      throw e;
    }
  });
  return server;
}
