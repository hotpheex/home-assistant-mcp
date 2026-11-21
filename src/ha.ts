import type { ConfigKind } from './policy.ts';

export type Command = { type: string } & Record<string, unknown>;

export interface RestRequest {
  method: 'GET' | 'POST' | 'DELETE';
  path: string;
  body?: unknown;
}

export const TARGET_KEYS = ['entity_id', 'device_id', 'area_id', 'floor_id', 'label_id'] as const;

export const HELPER_DOMAINS = [
  'input_boolean',
  'input_number',
  'input_select',
  'input_text',
  'input_datetime',
  'input_button',
  'counter',
  'timer',
  'schedule',
] as const;

export const COLLECTION_UPDATE_COMMANDS: ReadonlySet<string> = new Set([...HELPER_DOMAINS, 'zone'].map((d) => `${d}/update`));

export const ENTITY_NAME_FIELDS = ['name', 'icon', 'aliases'] as const;

export const FLOW_ID = /^[0-9A-Za-z]+$/;
export const FLOW_PATH = '/api/config/config_entries/flow';
export const OPTIONS_PATH = '/api/config/config_entries/options/flow';
export const HELPER_LISTS = {
  handlers: '/api/config/config_entries/flow_handlers?type=helper',
  entries: '/api/config/config_entries/entry?type=helper',
} as const;

export const isSafeConfigId = (id: string) => id.length > 0 && id !== '.' && id !== '..' && !id.includes('/');

export const configPath = (kind: ConfigKind, id: string) => `/api/config/${kind}/config/${encodeURIComponent(id)}`;

const splitHelperId = (id: string) => [id.slice(0, id.indexOf('.')), id.slice(id.indexOf('.') + 1)] as const;

export const collectionOf = (kind: ConfigKind, id: string) =>
  kind === 'helper' ? splitHelperId(id) : kind === 'zone' ? (['zone', id] as const) : undefined;

// HA identifies the default dashboard by omitting `url_path`, even after migrating it to `lovelace`.
export const dashboardPath = (id: string) => (id === 'lovelace' ? {} : { url_path: id });
