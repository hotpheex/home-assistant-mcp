import { readFileSync } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';
import { NAME_LOOKUP } from './evaluator.ts';
import { expiryWarnings } from './auth.ts';
import { HaUnavailable, openGate } from './gate.ts';
import type { Log } from './log.ts';
import { parsePolicy, policyWarnings } from './policy.ts';
import { unknownNames } from './resolver.ts';
import { readSettings, readTokens, SettingsError } from './settings.ts';

/** How long `check` waits for HA to accept its connection, as long as the HA client's own connect timeout. */
const CONNECT_WAIT_MS = 10_000;

/**
 * Validates a Policy with startup's errors, digest and warnings; given HAMCP_HA_URL, also resolves its names
 * against live HA and logs each unknown one as an error. Returns whether it found no error.
 */
export async function check(path: string, env: Record<string, string | undefined>, log: Log): Promise<boolean> {
  const policy = parsePolicy(readFileSync(path, 'utf8'));
  log('info', 'policy loaded', { policy_sha256: policy.sha256 });
  for (const warning of [...policyWarnings(policy, new Date()), ...expiryWarnings(policy, new Date())]) log('warn', warning);
  if (env.HAMCP_HA_URL === undefined) return true;

  const { HAMCP_HA_URL } = readSettings(env, path);
  if (!env.HAMCP_HA_USERS_TOKEN && !env.HAMCP_HA_USERS_TOKEN_FILE) {
    throw new SettingsError('check resolves names at the users tier; set HAMCP_HA_USERS_TOKEN or HAMCP_HA_USERS_TOKEN_FILE');
  }
  let fatal: string | undefined;
  const gate = openGate(HAMCP_HA_URL, readTokens(env, ['users']), log, (reason) => (fatal ??= reason));
  try {
    for (const deadline = Date.now() + CONNECT_WAIT_MS; ; await sleep(100)) {
      try {
        const unknown = await unknownNames(policy, (command) => gate.send(NAME_LOOKUP, command));
        for (const problem of unknown) log('error', problem);
        return unknown.length === 0;
      } catch (e) {
        if (!(e instanceof HaUnavailable)) throw e;
        if (fatal) throw new Error(fatal);
        if (Date.now() > deadline) throw new Error(`Home Assistant at ${HAMCP_HA_URL} is unavailable`);
      }
    }
  } finally {
    gate.close();
  }
}
