import * as z from 'zod';
import {
  dashboardDelete,
  decideBlueprintWrite,
  decideConfigRead,
  decideConfigWrite,
  mergedUpdate,
  type Allowed,
  type BlueprintWrite,
  type ConfigWrite,
} from '../evaluator.ts';
import { collectionOf, configPath, dashboardPath, ENTITY_NAME_FIELDS, HELPER_DOMAINS, isSafeConfigId } from '../ha.ts';
import { CONFIG_KINDS } from '../policy.ts';
import { maskSecrets, stripBearerTokens } from '../redaction.ts';
import {
  bodyFor,
  defineTool,
  entityId,
  epochSecondsToIso,
  lackingKinds,
  MASKED,
  page,
  PAGED,
  pageOf,
  text,
  ToolFailure,
  writeResult,
  type ToolRuntime,
} from './runtime.ts';

const scriptKind = z.enum(['automation', 'script']);
const itemId = z.string().min(1).describe("The automation's config `id`, or the script's object id (the part after `script.`).");

const configKind = z.enum(CONFIG_KINDS);
const helperId = new RegExp(`^(${HELPER_DOMAINS.join('|')})\\.[a-z0-9_]+$`);
const HELPER_ID_RULE = 'must be <helper domain>.<id>, such as input_boolean.guest_mode';
const NOT_A_CONFIG = 'a wizard helper is set up through its flow, not as a config';
const SAFE_ID_RULE = 'must not be ., .. or contain /';
const isRestKind = (kind: ConfigWrite['kind']) => kind === 'automation' || kind === 'script' || kind === 'scene';

async function stored(rt: ToolRuntime, allowed: Allowed | undefined, kind: ConfigWrite['kind'], id: string): Promise<Record<string, unknown> | undefined> {
  const collection = collectionOf(kind, id);
  if (!collection) return await rt.rest<Record<string, unknown> | undefined>({ method: 'GET', path: configPath(kind, id) }, allowed, { stripTokens: false });
  const [domain, item] = collection;
  return (await rt.send<Record<string, unknown>[]>({ type: `${domain}/list` }, allowed)).find((h) => h.id === item);
}

async function dashboardLookup(rt: ToolRuntime, { action, id }: ConfigWrite, allowed: Allowed): Promise<Allowed> {
  const lookup = decideConfigRead(rt.policy, rt.auth.caller, 'dashboard').allowed;
  const listed = id === 'lovelace' ? [{ url_path: id }] : await rt.send<{ id?: string; url_path: string }[]>({ type: 'lovelace/dashboards/list' }, lookup);
  const item = listed.find((d) => d.url_path === id);
  if (action === 'create' && item) throw new ToolFailure(`The dashboard ${id} already exists; update it instead.`);
  if (action === 'create') return allowed;
  if (!item) throw new ToolFailure(`The dashboard ${id} does not exist; create it instead.`);
  if (action === 'update') {
    const layout = await rt.send<Record<string, unknown>>({ type: 'lovelace/config', ...dashboardPath(id) }, lookup).catch((e: unknown) => {
      if (e instanceof ToolFailure && e.code === 'config_not_found') return {};
      throw e;
    });
    return mergedUpdate(allowed, layout);
  }
  if (item.id === undefined) throw new ToolFailure(`The dashboard ${id} is defined in YAML, so only its YAML can remove it.`);
  return dashboardDelete(allowed, item.id);
}

export const getConfig = defineTool({
  operation: 'config_read',
  title: 'Get config',
  description: [
    'Returns the stored configuration of one automation, script, scene, helper (input_*, counter, timer or schedule) or zone.',
    'Name an automation or script by `kind` and `entity_id`, such as automation.porch_light; a scene or zone by its config `id`; and a helper by `id` as `<domain>.<id>`, such as input_boolean.guest_mode.',
    'Scene, helper and zone configs are served only to a Caller that may write that kind.',
    MASKED,
    'Example: {"kind": "automation", "entity_id": "automation.porch_light"}.',
  ].join(' '),
  input: z
    .strictObject({
      kind: configKind.describe('automation, script, scene, helper or zone.'),
      entity_id: entityId.optional().describe('For an automation or script: its entity, such as automation.porch_light.'),
      id: z.string().min(1).optional().describe('For a scene or zone: its config id. For a helper: <domain>.<id>, such as input_boolean.guest_mode.'),
    })
    .superRefine(({ kind, entity_id, id }, ctx) => {
      const byEntity = kind === 'automation' || kind === 'script';
      const a = kind === 'automation' ? 'an' : 'a';
      const [taken, other] = byEntity ? (['entity_id', 'id'] as const) : (['id', 'entity_id'] as const);
      if ({ entity_id, id }[other] !== undefined) ctx.addIssue({ code: 'custom', path: [other], message: `is not taken for ${a} ${kind}, which takes only ${taken}` });
      if (byEntity && entity_id === undefined) ctx.addIssue({ code: 'custom', path: ['entity_id'], message: `is required for ${a} ${kind}` });
      if (byEntity && entity_id?.startsWith(`${kind}.`) === false) {
        ctx.addIssue({ code: 'custom', path: ['entity_id'], message: `its domain must match kind: ${a} ${kind} takes ${kind}.<id>` });
      }
      if (!byEntity && id === undefined) ctx.addIssue({ code: 'custom', path: ['id'], message: `is required for a ${kind}` });
      if (kind === 'scene' && id !== undefined && !isSafeConfigId(id)) ctx.addIssue({ code: 'custom', path: ['id'], message: SAFE_ID_RULE });
      if (kind === 'helper' && id !== undefined && !helperId.test(id)) ctx.addIssue({ code: 'custom', path: ['id'], message: HELPER_ID_RULE });
      if (kind === 'entity_name') ctx.addIssue({ code: 'custom', path: ['kind'], message: "entity_name has no config to read; ha_get_registry lists each entity's name and icon" });
      if (kind === 'dashboard') ctx.addIssue({ code: 'custom', path: ['kind'], message: 'a dashboard is read with the dashboard tool' });
      if (kind === 'helper_entry') ctx.addIssue({ code: 'custom', path: ['kind'], message: NOT_A_CONFIG });
    }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  decide: ({ kind }, policy, caller) => ({ ...decideConfigRead(policy, caller, kind), lacking: `${kind} config`, request: { kind } }),
  async run({ kind, entity_id, id }, rt) {
    if (kind === 'automation' || kind === 'script') return text(await rt.read({ type: `${kind}/config`, entity_id }));
    const config = await stored(rt, rt.allowed, kind, id!);
    if (config === undefined) throw new ToolFailure(`${kind.charAt(0).toUpperCase()}${kind.slice(1)} ${id} not found.`);
    return text({ config: maskSecrets(stripBearerTokens(config)) });
  },
});

type TraceSummary = { timestamp: { start: string } };

async function assertItemExists(rt: ToolRuntime, kind: string, id: string) {
  const entities = await rt.send<{ platform: string; unique_id: string }[]>({ type: 'config/entity_registry/list' });
  if (entities.some((e) => e.platform === kind && e.unique_id === id)) return;
  throw new ToolFailure(`No ${kind} has the id ${id}. Name it by an automation's config id or a script's object id (the part after script.), not by its entity_id.`);
}

export const listTraces = defineTool({
  operation: 'config_read',
  title: 'List traces',
  description: [
    'Lists the stored runs of one automation or script, newest first, as summaries: run_id, start and finish time, state, last step, what triggered it and any error.',
    "Name the item by `kind` (automation or script) and `id`: an automation's config `id` from its config, or a script's object id, the part of its entity_id after `script.`.",
    'An id that names no automation or script is refused; one with no stored runs returns an empty list.',
    MASKED,
    PAGED,
    'Example: {"kind": "script", "id": "morning"} lists the runs of script.morning.',
  ].join(' '),
  narrowing: 'a smaller limit',
  input: z.strictObject({ kind: scriptKind.describe('automation or script.'), id: itemId, ...page }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run({ kind, id, ...paging }, rt) {
    const traces = await rt.read<TraceSummary[]>({ type: 'trace/list', domain: kind, item_id: id });
    if (traces.length === 0) await assertItemExists(rt, kind, id);
    return text(pageOf('traces', traces.sort((a, b) => Date.parse(b.timestamp.start) - Date.parse(a.timestamp.start)), paging));
  },
});

const TRACE_SECTIONS = ['trace', 'config', 'blueprint_inputs', 'context'] as const;

export const getTrace = defineTool({
  operation: 'config_read',
  title: 'Get trace',
  description: [
    'Returns one run of an automation or script: its summary, plus the `sections` asked for.',
    'The sections are `trace` (each step with its variables and result), `config` (the config the run used), `blueprint_inputs` and `context` (what caused the run).',
    "Name the run by `kind`, `id` (an automation's config `id` or a script's object id) and `run_id` from its trace list.",
    'Camera, image and media_player bearer tokens are removed.',
    MASKED,
    'Example: {"kind": "automation", "id": "porch_light_1", "run_id": "1a2b3c", "sections": ["trace"]}.',
  ].join(' '),
  narrowing: 'fewer sections',
  input: z.strictObject({
    kind: scriptKind.describe('automation or script.'),
    id: itemId,
    run_id: z.string().min(1).describe('The run, from its trace list.'),
    sections: z.array(z.enum(TRACE_SECTIONS)).min(1).describe('The parts to return beyond the summary.'),
  }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run({ kind, id, run_id, sections }, rt) {
    const trace = await rt.read<Record<string, unknown>>({ type: 'trace/get', domain: kind, item_id: id, run_id }).catch(async (e: unknown) => {
      if (e instanceof ToolFailure) await assertItemExists(rt, kind, id);
      throw e;
    });
    const left = TRACE_SECTIONS.filter((s) => !sections.includes(s)) as string[];
    return text(Object.fromEntries(Object.entries(trace).filter(([key]) => !left.includes(key))));
  },
});

const LOG_LEVELS = ['debug', 'info', 'warning', 'error', 'critical'] as const;
type LogEntry = { name: string; level: string; message: string[]; source: unknown[]; timestamp: number; first_occurred: number };

export const getLogs = defineTool({
  operation: 'config_read',
  title: 'Get system log',
  description: [
    "Lists Home Assistant's system log, newest first: the warnings and errors that integrations and automations logged, each with its logger name, level, messages, source file and line, exception text, count, and the first and last times it occurred.",
    'Filter by minimum `level` (debug, info, warning, error or critical) and by `query`, a case-insensitive substring of the logger name, the source or a message.',
    MASKED,
    PAGED,
    'Example: {"level": "error", "query": "automation"} lists the errors automations logged.',
  ].join(' '),
  narrowing: 'a level, a query or a smaller limit',
  input: z.strictObject({
    level: z.enum(LOG_LEVELS).optional().describe('The lowest level to list.'),
    query: z.string().min(1).optional().describe('Case-insensitive substring of the logger name, the source or a message.'),
    ...page,
  }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run({ level, query, ...paging }, rt) {
    const entries = await rt.read<LogEntry[]>({ type: 'system_log/list' });
    const rank = (name: string) => LOG_LEVELS.findIndex((l) => l === name.toLowerCase());
    const shown = entries
      .filter((e) => level === undefined || rank(e.level) >= rank(level))
      .filter((e) => query === undefined || [e.name, e.source.join(':'), ...e.message].some((v) => v.toLowerCase().includes(query.toLowerCase())))
      .map((e) => ({ ...e, timestamp: epochSecondsToIso(e.timestamp), first_occurred: epochSecondsToIso(e.first_occurred) }));
    return text(pageOf('entries', shown, paging));
  },
});

type BlueprintEntry = { metadata: { name: string; description?: string; input?: unknown; source_url?: string } } | { error: string };

export const listBlueprints = defineTool({
  operation: 'config_read',
  title: 'List blueprints',
  description: [
    'Lists the installed automation and script blueprints, sorted by domain and path, each with its name, description, inputs and source URL, or the error that stopped it loading.',
    'Filter by `domain` (automation or script); an automation or script uses a blueprint by its `path`.',
    MASKED,
    PAGED,
    'Example: {"domain": "automation"} lists the automation blueprints.',
  ].join(' '),
  narrowing: 'a domain or a smaller limit',
  input: z.strictObject({ domain: scriptKind.optional().describe('automation or script; both when omitted.'), ...page }),
  annotations: { readOnlyHint: true, destructiveHint: false },
  async run({ domain, ...paging }, rt) {
    const listed = await Promise.all(
      (domain === undefined ? scriptKind.options : [domain]).map(async (d) =>
        Object.entries(await rt.read<Record<string, BlueprintEntry>>({ type: 'blueprint/list', domain: d }))
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([path, entry]) => {
            if ('error' in entry) return { domain: d, path, error: entry.error };
            const { name, description, input, source_url } = entry.metadata;
            return { domain: d, path, name, description, inputs: input, source_url };
          }),
      ),
    );
    return text(pageOf('blueprints', listed.flat(), paging));
  },
});

const DASHBOARD_SIDEBAR = ['title', 'icon', 'show_in_sidebar', 'require_admin'];

export const writeConfig = defineTool({
  operation: 'config_write',
  title: 'Write config',
  description: [
    'Creates, updates or deletes one automation, script, scene, helper (input_*, counter, timer or schedule), zone or dashboard; this is admin-equivalent, because an automation or script can do anything in Home Assistant.',
    "Name the item by `kind` and `id`: an automation's, scene's or zone's config `id`, a script's object id (the part after `script.`), a helper's `<domain>.<id>`, such as input_boolean.guest_mode, or a dashboard's URL path, where `lovelace`, the default dashboard, can only be updated; a new dashboard takes only its sidebar settings (`title`, `icon`, `show_in_sidebar`, `require_admin`).",
    'An update sends only the top-level keys it changes and keeps the rest; creating an automation, script or scene refuses an id that exists, and a new helper or zone takes its id from its `name`, which the result returns.',
    'A config that carries **REDACTED** from a config read is refused, so put the real value in its place first.',
    'Example: {"kind": "automation", "action": "update", "id": "porch_light_1", "config": {"alias": "Porch light at dusk"}}.',
    'Kind `entity_name` only updates the `name`, `icon` or `aliases` of the entity whose entity_id is `id`; voice assistants match its aliases.',
  ].join(' '),
  input: z
    .strictObject({
      kind: configKind.describe('automation, script, scene, helper, zone, entity_name or dashboard.'),
      action: z.enum(['create', 'update', 'delete']).describe('create, update or delete.'),
      id: z.string().min(1).describe("An automation's, scene's or zone's config id, a script's object id, a helper's <domain>.<id>, an entity_name's entity_id, or a dashboard's URL path."),
      config: z.record(z.string(), z.unknown()).optional().describe('The config to create, or the top-level keys to change; omitted for delete.'),
    })
    .superRefine(({ kind, action, id, config }, ctx) => {
      if (isRestKind(kind) && !isSafeConfigId(id)) ctx.addIssue({ code: 'custom', path: ['id'], message: SAFE_ID_RULE });
      if (kind === 'helper' && !helperId.test(id)) ctx.addIssue({ code: 'custom', path: ['id'], message: HELPER_ID_RULE });
      bodyFor(action, 'config', config, ctx);
      if (kind === 'entity_name' && action !== 'update') ctx.addIssue({ code: 'custom', path: ['action'], message: 'entity_name takes only update' });
      if (kind === 'entity_name' && !entityId.safeParse(id).success) ctx.addIssue({ code: 'custom', path: ['id'], message: 'must be an entity_id such as light.kitchen' });
      if (kind === 'dashboard' && id === 'lovelace' && action !== 'update') ctx.addIssue({ code: 'custom', path: ['id'], message: 'the default dashboard lovelace can only be updated' });
      if (kind === 'dashboard' && action === 'create' && Object.keys(config ?? {}).some((k) => !DASHBOARD_SIDEBAR.includes(k))) {
        ctx.addIssue({ code: 'custom', path: ['config'], message: 'a new dashboard takes only title, icon, show_in_sidebar and require_admin' });
      }
      if (kind === 'helper_entry') ctx.addIssue({ code: 'custom', path: ['kind'], message: NOT_A_CONFIG });
    }),
  annotations: { readOnlyHint: false, destructiveHint: true },
  kinds: CONFIG_KINDS.filter((k) => k !== 'helper_entry'),
  decide: (change: ConfigWrite, policy, caller) => ({
    ...decideConfigWrite(policy, caller, change),
    lacking: lackingKinds([change.kind]),
    request: { kind: change.kind, action: change.action, id: change.id },
  }),
  async run(change: ConfigWrite, rt) {
    const { kind, action, id } = change;
    const names = { kind, action, id };
    if (!rt.allowed) throw new Error('config write sent without an Allowed');
    let allowed: Allowed = rt.allowed;
    const others = kind === 'entity_name' ? Object.keys(change.config ?? {}).filter((k) => !(ENTITY_NAME_FIELDS as readonly string[]).includes(k)) : [];
    if (others.length > 0) {
      rt.audit({ ...names, decision: 'deny', reason: 'entity_name changes only name, icon and aliases' });
      throw new ToolFailure(`Denied: entity_name changes only name, icon and aliases, not ${others.map((k) => `config.${k}`).join(', ')}. Nothing was sent to Home Assistant.`);
    }
    rt.refuseRedacted(names, 'config', change.config);
    const result = await rt.writing(names, rt.grants, async () => {
      if (kind === 'dashboard') allowed = await dashboardLookup(rt, change, allowed);
      else if (kind !== 'entity_name' && (action === 'update' || (!collectionOf(kind, id) && action === 'create'))) {
        const item = await stored(rt, decideConfigRead(rt.policy, rt.auth.caller, kind).allowed, kind, id);
        if (action === 'create' && item) throw new ToolFailure(`The ${kind} ${id} already exists; update it instead.`);
        if (action === 'update' && !item) throw new ToolFailure(`The ${kind} ${id} does not exist; create it instead.`);
        if (item) allowed = mergedUpdate(allowed, item);
      }
      return await rt.executeWrite(allowed);
    });
    return writeResult({ ...names, result: maskSecrets(result) });
  },
});

// HA appends `.yaml` on blueprint/save but not on blueprint/delete, so normalize here.
const blueprintPath = z
  .string()
  .regex(/^\w[\w.-]*(\/\w[\w.-]*)*$/, 'must be a relative path such as mine/porch_light.yaml')
  .transform((p) => (p.endsWith('.yaml') ? p : `${p}.yaml`));

export const writeBlueprint = defineTool({
  operation: 'config_write',
  title: 'Write blueprint',
  description: [
    "Creates, updates or deletes one automation or script blueprint from YAML the Caller supplies; it needs a config write of the blueprint's domain, and is admin-equivalent as that is.",
    "Name the blueprint by `domain` and `path` within that domain's blueprint folder, such as mine/porch_light.yaml; `.yaml` is added when left off.",
    'A create refuses a path that exists and an update replaces the whole file, so send the full YAML; importing a blueprint from a URL is not offered, so fetch the YAML first.',
    'YAML that carries **REDACTED** from a read is refused, so put the real value in its place first.',
    'Example: {"domain": "script", "action": "delete", "path": "mine/ping.yaml"}.',
  ].join(' '),
  input: z
    .strictObject({
      domain: scriptKind.describe('automation or script.'),
      action: z.enum(['create', 'update', 'delete']).describe('create, update or delete.'),
      path: blueprintPath.describe('The path within the domain blueprint folder, such as mine/porch_light.yaml.'),
      yaml: z.string().min(1).optional().describe('The whole blueprint YAML; omitted for delete.'),
    })
    .superRefine(({ action, yaml }, ctx) => bodyFor(action, 'yaml', yaml, ctx)),
  annotations: { readOnlyHint: false, destructiveHint: true },
  kinds: ['automation', 'script'],
  decide: (change: BlueprintWrite, policy, caller) => ({
    ...decideBlueprintWrite(policy, caller, change),
    lacking: lackingKinds([change.domain]),
    request: { domain: change.domain, action: change.action, path: change.path },
  }),
  async run({ domain, action, path, yaml }: BlueprintWrite, rt) {
    if (!rt.allowed) throw new Error('blueprint write sent without an Allowed');
    const names = { domain, action, path };
    rt.refuseRedacted(names, 'yaml', yaml);
    const allowed = rt.allowed;
    const result = await rt.writing(names, rt.grants, () => rt.executeWrite(allowed));
    return writeResult({ ...names, result });
  },
});
