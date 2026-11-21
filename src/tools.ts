import { ProtocolError, ProtocolErrorCode, Server, type CallToolResult, type Tool } from '@modelcontextprotocol/server';
import * as z from 'zod';
import pkg from '../package.json' with { type: 'json' };
import type { Authenticated } from './auth.ts';
import { decideRead, grantsFor, writersOf, type Operation } from './evaluator.ts';
import type { Gate } from './gate.ts';
import { auditFor, type Audit } from './log.ts';
import type { Policy } from './policy.ts';
import { callService, helperFlow } from './tools/actions.ts';
import { getConfig, getLogs, getTrace, listBlueprints, listTraces, writeBlueprint, writeConfig } from './tools/config.ts';
import { getDashboard, getHistory, getLogbook, getRegistry, getStates, getStatistics, listServices, renderTemplate } from './tools/reads.ts';
import { CHAR_CAP, createRuntime, failure, lackingKinds, ToolFailure, type AuditOptions, type ToolSpec } from './tools/runtime.ts';

export type { AuditOptions };

const TOOLS = {
  ha_get_states: getStates,
  ha_get_history: getHistory,
  ha_get_logbook: getLogbook,
  ha_get_registry: getRegistry,
  ha_list_services: listServices,
  ha_get_config: getConfig,
  ha_list_traces: listTraces,
  ha_get_trace: getTrace,
  ha_write_config: writeConfig,
  ha_call_service: callService,
  ha_get_statistics: getStatistics,
  ha_render_template: renderTemplate,
  ha_get_logs: getLogs,
  ha_get_dashboard: getDashboard,
  ha_list_blueprints: listBlueprints,
  ha_write_blueprint: writeBlueprint,
  ha_helper_flow: helperFlow,
} satisfies Record<string, ToolSpec<z.ZodType>>;

export type ToolName = keyof typeof TOOLS;

export const TOOL_KIND = Object.fromEntries(
  (Object.entries(TOOLS) as [ToolName, ToolSpec<z.ZodType>][]).map(([name, spec]) => [name, spec.operation]),
) as Record<ToolName, Operation>;

const OPERATION_NAME: Record<Operation, string> = {
  plain_read: 'plain read',
  config_read: 'config read',
  service_call: 'service calls',
  config_write: 'config writes',
};

const READS: ReadonlySet<Operation> = new Set(['plain_read', 'config_read']);
const charsOf = (result: CallToolResult) => result.content.reduce((n, c) => n + (c.type === 'text' ? c.text.length : 0), 0);

const DEFINITIONS = Object.fromEntries(
  Object.entries(TOOLS).map(([name, t]) => [
    name,
    { name, title: t.title, description: t.description, inputSchema: z.toJSONSchema(t.input, { io: 'input' }), annotations: t.annotations } as Tool,
  ]),
) as Record<ToolName, Tool>;

const isTool = (name: string): name is ToolName => Object.hasOwn(TOOLS, name);

const GENERAL_INSTRUCTIONS = [
  'Every call is checked against the Grants this Caller holds. A denied call means there is no Grant for it, so do not retry it or try to reach the same result another way.',
  'Lists return `total` and `has_more`: while `has_more` is true, call again with `offset` raised by `limit`. A response that is too large is refused rather than cut off, so narrow the query and call again.',
];
const instructionsFor = (visible: ToolName[]) => [...visible.flatMap((name) => TOOLS[name].instruction ?? []), ...GENERAL_INSTRUCTIONS].join('\n');

const deniedFor = (lacking: string) => failure(`Denied: this Caller holds no Grant for ${lacking}. Do not retry this call.`);

export function buildServer(policy: Policy, gate: Gate, audit: Audit, auth: Authenticated, options: AuditOptions): Server {
  const holds = (name: ToolName) => {
    const tool = TOOLS[name];
    return tool.kinds === undefined
      ? grantsFor(policy, auth.caller, tool.operation).length > 0
      : tool.kinds.some((k) => writersOf(policy, auth.caller, k).length > 0);
  };
  const visible = (Object.keys(TOOLS) as ToolName[]).filter(holds);
  const server = new Server(
    { name: pkg.name, version: pkg.version },
    {
      capabilities: { tools: {} },
      instructions: instructionsFor(visible),
      cacheHints: { 'tools/list': { cacheScope: 'private', ttlMs: 0 } },
    },
  );
  server.setRequestHandler('tools/list', () => ({ tools: visible.map((name) => DEFINITIONS[name]) }));
  server.setRequestHandler('tools/call', async ({ params }) => {
    const { name } = params;
    if (!isTool(name)) throw new ProtocolError(ProtocolErrorCode.InvalidParams, `Tool ${name} not found`);
    const tool = TOOLS[name];
    const { operation } = tool;
    if (!holds(name)) {
      auditFor(audit, auth, operation, name)({ decision: 'deny', grants: [] });
      return deniedFor(tool.kinds === undefined ? OPERATION_NAME[operation] : lackingKinds(tool.kinds));
    }
    const args = tool.input.safeParse(params.arguments ?? {});
    if (!args.success) {
      return failure(`Input validation error: ${args.error.issues.map((i) => `${i.path.join('.') || '(arguments)'}: ${i.message}`).join('; ')}`);
    }
    const decided = tool.decide?.(args.data, policy, auth.caller) ?? {
      ...(operation === 'plain_read' || operation === 'config_read'
        ? decideRead(policy, auth.caller, operation)
        : { grants: grantsFor(policy, auth.caller, operation) }),
      lacking: OPERATION_NAME[operation],
      request: {},
    };
    const reading = READS.has(operation) || (tool.reads?.(args.data) ?? false);
    const audited = auditFor(audit, auth, reading && operation === 'config_write' ? 'config_read' : operation, name);
    if (decided.grants.length === 0) {
      audited({ ...decided.request, decision: 'deny', grants: [] });
      return deniedFor(decided.lacking);
    }
    if (options.auditReads && reading) {
      audited({ decision: 'allow', grants: decided.grants, request: tool.auditable?.(args.data) ?? args.data });
    }
    try {
      const rt = createRuntime(gate, decided, policy, auth, audited, options);
      const result = await tool.run(args.data, rt);
      if (reading && charsOf(result) > CHAR_CAP) {
        const over = `The response is over ${CHAR_CAP} characters, so nothing was returned`;
        return failure(tool.narrowing === undefined ? `${over}, and this tool offers no narrower query.` : `${over}: narrow the query with ${tool.narrowing}.`);
      }
      return server.projectCallToolResult(result, undefined);
    } catch (e) {
      if (e instanceof ToolFailure) return failure(e.message);
      throw e;
    }
  });
  return server;
}
