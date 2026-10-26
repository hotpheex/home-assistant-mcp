/** One JSON object per stdout line, so a log collector can store the lines and filter audit records. */
export type Write = (line: string) => void;
export type Log = (level: 'info' | 'warn' | 'error', msg: string, fields?: Record<string, unknown>) => void;
/** An Audit record: names only, never service data, bodies or responses. */
export type Audit = (record: Record<string, unknown>) => void;

export function logger(write: Write): { log: Log; audit: Audit } {
  const time = () => new Date().toISOString();
  return {
    log: (level, msg, fields) => write(JSON.stringify({ time: time(), level, msg, ...fields })),
    audit: (record) => write(JSON.stringify({ time: time(), audit: true, ...record })),
  };
}
