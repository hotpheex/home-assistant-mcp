export type Log = (level: 'info' | 'warn' | 'error', msg: string, fields?: Record<string, unknown>) => void;
/** An Audit record: names only, never service data, bodies or responses. */
export type Audit = (record: Record<string, unknown>) => void;

/** Binds the fields every record of one request shares: who asked (never the key itself), the Operation and the tool. */
export const auditFor =
  (audit: Audit, who: { caller?: string; keyHashPrefix?: string }, operation: string, tool?: string): Audit =>
  (record) =>
    audit({ caller: who.caller, key_hash_prefix: who.keyHashPrefix, operation, tool, ...record });

/** One JSON object per stdout line, so a log collector can store the lines and filter audit records. */
export function logger(write: (line: string) => void): { log: Log; audit: Audit } {
  const time = () => new Date().toISOString();
  return {
    log: (level, msg, fields) => write(JSON.stringify({ time: time(), level, msg, ...fields })),
    audit: (record) => write(JSON.stringify({ time: time(), audit: true, ...record })),
  };
}
