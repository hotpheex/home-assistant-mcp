import type { CallToolResult } from '@modelcontextprotocol/server';
import * as z from 'zod';
import type { Authenticated } from '../auth.ts';
import type { Allowed, ConfigKind, Operation } from '../evaluator.ts';
import { HaUnavailable, OutcomeUnknown, type Gate } from '../gate.ts';
import type { Command, RestRequest } from '../ha.ts';
import type { Audit } from '../log.ts';
import type { Policy } from '../policy.ts';
import { maskSecrets, REDACTED, redactedPath, stripBearerTokens } from '../redaction.ts';

export interface AuditOptions {
  auditReads: boolean;
  auditWrites: boolean;
}

export interface Decided {
  grants: number[];
  lacking: string;
  request: Record<string, unknown>;
  allowed?: Allowed;
}

export interface ToolRuntime {
  readonly policy: Policy;
  readonly auth: Authenticated;
  readonly grants: number[];
  readonly allowed: Allowed | undefined;
  readonly audit: Audit;
  read<T>(command: Command): Promise<T>;
  send<T>(command: Command, allowed?: Allowed): Promise<T>;
  rest<T>(request: RestRequest, allowed?: Allowed, opts?: { stripTokens?: boolean }): Promise<T>;
  subscribeOnce<T>(command: Command): Promise<T>;
  executeWrite<T>(allowed: Allowed): Promise<T>;
  writing<T>(
    names: Record<string, unknown>,
    grants: number[],
    write: () => Promise<T>,
    done?: (result: T) => Record<string, unknown>,
    allowExtra?: Record<string, unknown>,
  ): Promise<T>;
  refuseRedacted(names: Record<string, unknown>, field: string, value: unknown): void;
}

export interface ToolSpec<Input extends z.ZodType> {
  operation: Operation;
  title: string;
  description: string;
  input: Input;
  annotations: { readOnlyHint: boolean; destructiveHint: boolean };
  narrowing?: string;
  instruction?: string;
  kinds?: readonly ConfigKind[];
  decide?(args: z.output<Input>, policy: Policy, caller: string): Decided;
  auditable?(args: z.output<Input>): Record<string, unknown>;
  reads?(args: z.output<Input>): boolean;
  run(args: z.output<Input>, rt: ToolRuntime): Promise<CallToolResult>;
}

export const defineTool = <Input extends z.ZodType>(spec: ToolSpec<Input>) => spec as unknown as ToolSpec<z.ZodType>;

export const PAGED = 'Results come in pages: `limit` (default 50, at most 500) and `offset` pick the page, and the response gives `total` and `has_more`.';
export const MASKED = 'Values that look like secrets, such as passwords, tokens, API keys and URL credentials, come back as **REDACTED**; this is best-effort, so other secrets may still show.';

export const page = {
  limit: z.number().int().min(1).max(500).default(50).describe('Page size, at most 500.'),
  offset: z.number().int().min(0).default(0).describe('Entries to skip.'),
};

export type Page = { limit: number; offset: number };

export const pageOf = (key: string, items: unknown[], { limit, offset }: Page) => ({
  total: items.length,
  offset,
  has_more: offset + limit < items.length,
  [key]: items.slice(offset, offset + limit),
});

export const slug = z.string().regex(/^[a-z0-9_]+$/);
export const entityId = z.string().regex(/^[a-z0-9_]+\.[a-z0-9_]+$/, 'must be an entity_id such as light.kitchen');

export const timeWindow = {
  start: z.iso.datetime({ offset: true }).optional().describe('ISO 8601 start time.'),
  end: z.iso.datetime({ offset: true }).optional().describe('ISO 8601 end time; defaults to now.'),
};

export const epochSecondsToIso = (seconds: number) => new Date(Math.round(seconds * 1000)).toISOString();

// Claude Code saves text results over 50,000 JS string chars to disk; keep responses under that threshold.
export const CHAR_CAP = 48_000;

export const text = (value: unknown): CallToolResult => ({ content: [{ type: 'text', text: JSON.stringify(value) }] });
export const failure = (message: string): CallToolResult => ({ isError: true, content: [{ type: 'text', text: message }] });
export const lackingKinds = (kinds: readonly string[]) => `config writes of ${kinds.join(' or ')}`;

export function bodyFor(action: string, key: string, body: unknown, ctx: z.RefinementCtx): void {
  if (action !== 'delete' && body === undefined) ctx.addIssue({ code: 'custom', path: [key], message: `is required to ${action}` });
  if (action === 'delete' && body !== undefined) ctx.addIssue({ code: 'custom', path: [key], message: 'is not taken by delete' });
}

export class ToolFailure extends Error {
  code?: string;
}

export function windowOf(args: { start?: string; end?: string }, hours: number) {
  const end = args.end === undefined ? Date.now() : Date.parse(args.end);
  const start = args.start === undefined ? end - hours * 3_600_000 : Date.parse(args.start);
  const [from, to] = [new Date(start).toISOString(), new Date(end).toISOString()];
  if (start > end) throw new ToolFailure(`Input validation error: start ${from} is after end ${to}.`);
  return { start: from, end: to };
}

export function writeResult(value: unknown): CallToolResult {
  const full = JSON.stringify(value);
  if (full.length <= CHAR_CAP) return text(value);
  const marker = `\n[truncated: the response was ${full.length} characters, over the ${CHAR_CAP}-character cap; the call ran]`;
  const kept = full.slice(0, CHAR_CAP - marker.length).replace(/[\uD800-\uDBFF]$/, '');
  return { content: [{ type: 'text', text: kept + marker }] };
}

function outage(e: unknown): unknown {
  if (e instanceof HaUnavailable) {
    return new ToolFailure(
      e.sent ? 'HA unavailable: Home Assistant did not answer. Try again later.' : 'HA unavailable: nothing was sent to Home Assistant. Try again later.',
    );
  }
  if (e instanceof OutcomeUnknown) {
    return new ToolFailure('Outcome unknown: the connection to Home Assistant dropped after the call was sent. Check state before retrying.');
  }
  return e;
}

async function unwrapHaResult(request: Promise<unknown>): Promise<unknown> {
  try {
    return stripBearerTokens(await request);
  } catch (e) {
    const refusal = e as { code?: unknown; message?: unknown } | null;
    // home-assistant-js-websocket rejects HA errors as plain `{ code, message }` objects rather than Error instances.
    if (!(e instanceof Error) && typeof refusal?.code === 'string' && typeof refusal.message === 'string') {
      throw Object.assign(new ToolFailure(`Home Assistant refused the request: ${refusal.message}`), { code: refusal.code });
    }
    throw outage(e);
  }
}

export function createRuntime(
  gate: Gate,
  decided: Decided,
  policy: Policy,
  auth: Authenticated,
  audit: Audit,
  options: AuditOptions,
): ToolRuntime {
  const requireAllowed = (allowed: Allowed | undefined): Allowed => {
    if (!allowed) throw new Error('HA request sent without an Allowed');
    return allowed;
  };

  const send = async <T>(command: Command, allowed: Allowed | undefined = decided.allowed): Promise<T> =>
    (await unwrapHaResult(gate.send(requireAllowed(allowed), command))) as T;

  const rest = async <T>(
    request: RestRequest,
    allowed: Allowed | undefined = decided.allowed,
    opts?: { stripTokens?: boolean },
  ): Promise<T> => {
    const answer = await gate.rest(requireAllowed(allowed), request).catch((e: unknown) => {
      throw outage(e);
    });
    if (answer.status === 404 && request.method === 'GET') return undefined as T;
    // HA flow steps failing schema validation return 400 with `{ errors }` while keeping the flow open.
    const errors = (answer.body as { errors?: unknown } | null)?.errors;
    if (answer.status === 400 && errors !== undefined) {
      throw new ToolFailure(`Home Assistant refused the input: ${JSON.stringify(maskSecrets(errors))}. The flow is still open: correct the input and submit the step again.`);
    }
    if (answer.status !== 200) {
      const message = (answer.body as { message?: string } | null)?.message ?? `HTTP ${answer.status}`;
      throw new ToolFailure(`Home Assistant refused the request: ${message}`);
    }
    return (opts?.stripTokens === false ? answer.body : stripBearerTokens(answer.body)) as T;
  };

  return {
    policy,
    auth,
    grants: decided.grants,
    allowed: decided.allowed,
    audit,
    read: async <T>(command: Command) => maskSecrets(await send(command)) as T,
    send,
    rest,
    subscribeOnce: async <T>(command: Command) => (await unwrapHaResult(gate.subscribeOnce(requireAllowed(decided.allowed), command))) as T,
    executeWrite: async <T>(allowed: Allowed) => {
      const { write } = allowed;
      if (!write) throw new Error('write sent without an Allowed write payload');
      return write.via === 'websocket' ? await send<T>(write.command, allowed) : await rest<T>(write.request, allowed);
    },
    async writing<T>(
      names: Record<string, unknown>,
      grants: number[],
      write: () => Promise<T>,
      done: (result: T) => Record<string, unknown> = () => ({}),
      allowExtra: Record<string, unknown> = {},
    ) {
      if (options.auditWrites) audit({ ...names, decision: 'allow', ...allowExtra, grants });
      const result = await write();
      if (options.auditWrites) audit({ ...names, outcome: 'done', ...done(result) });
      return result;
    },
    refuseRedacted(names: Record<string, unknown>, field: string, value: unknown) {
      const marked = redactedPath(value);
      if (marked === undefined) return;
      audit({ ...names, decision: 'deny', reason: `${field} carries a redacted value` });
      const at = typeof value === 'string' ? `line ${value.slice(0, value.indexOf(REDACTED)).split('\n').length}` : marked;
      throw new ToolFailure(`${field} carries a redacted value at ${at}: put the real value in its place. Nothing was sent to Home Assistant.`);
    },
  };
}
