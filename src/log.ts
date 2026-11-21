export type Log = (level: 'info' | 'warn' | 'error', msg: string, fields?: Record<string, unknown>) => void;
export type Audit = (record: Record<string, unknown>) => void;

export const auditFor =
  (audit: Audit, who: { caller?: string; keyHashPrefix?: string }, operation: string, tool?: string): Audit =>
  (record) =>
    audit({ caller: who.caller, key_hash_prefix: who.keyHashPrefix, operation, tool, ...record });

export function logger(write: (line: string) => void): { log: Log; audit: Audit } {
  const time = () => new Date().toISOString();
  return {
    log: (level, msg, fields) => write(JSON.stringify({ time: time(), level, msg, ...fields })),
    audit: (record) => write(JSON.stringify({ time: time(), audit: true, ...record })),
  };
}
