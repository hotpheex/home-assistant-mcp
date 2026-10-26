/** One JSON object per stdout line, so a log collector can store the lines and filter audit records. */
export type Write = (line: string) => void;
export type Log = (level: 'info' | 'warn' | 'error', msg: string, fields?: Record<string, unknown>) => void;
/** An Audit record: names only, never service data, bodies or responses. */
export type Audit = (record: Record<string, unknown>) => void;

const WRITES = new Set(['service_call', 'config_write']);

/** Refusals are always recorded; an allowed write only when the deployer sets HAMCP_AUDIT_WRITES. */
export const optedIn = (audit: Audit, writes: boolean): Audit => (record) => {
  if (record.decision === 'allow' && WRITES.has(String(record.operation)) && !writes) return;
  audit(record);
};

export function logger(write: Write): { log: Log; audit: Audit } {
  const time = () => new Date().toISOString();
  return {
    log: (level, msg, fields) => write(JSON.stringify({ time: time(), level, msg, ...fields })),
    audit: (record) => write(JSON.stringify({ time: time(), audit: true, ...record })),
  };
}
