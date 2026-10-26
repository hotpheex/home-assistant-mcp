import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { createMcpHandler, type AuthInfo } from '@modelcontextprotocol/server';
import { authenticator, type Authenticated } from './auth.ts';
import type { Gate } from './gate.ts';
import type { Audit, Log } from './log.ts';
import type { Policy } from './policy.ts';
import { buildServer } from './tools.ts';

const deny = (res: ServerResponse, status: number, headers: Record<string, string> = {}) => void res.writeHead(status, headers).end();

/** Streamable HTTP at /mcp for both protocol eras, statelessly. Each request is checked in order: Origin, key, then the SDK. */
export function createHttp(policy: Policy, allowedOrigins: ReadonlySet<string>, gate: Gate, log: Log, audit: Audit) {
  const authenticate = authenticator(policy);
  const mcp = createMcpHandler(({ authInfo }) => buildServer(policy, gate, audit, authInfo?.extra?.caller as Authenticated), {
    onerror: (e) => log('error', 'MCP request failed', { error: e.message }),
  });
  const handle = toNodeHandler(mcp);
  const http = createServer((req: IncomingMessage & { auth?: AuthInfo }, res) => {
    if (new URL(req.url ?? '/', 'http://x').pathname !== '/mcp') return deny(res, 404);
    const origin = req.headers.origin;
    if (origin !== undefined && !allowedOrigins.has(origin)) return deny(res, 403);
    const result = authenticate(req.headers.authorization, new Date());
    if (!result.ok) {
      const { reason, caller, keyHashPrefix } = result;
      audit({ operation: 'authenticate', decision: 'deny', reason, remote: req.socket.remoteAddress, caller, key_hash_prefix: keyHashPrefix });
      return deny(res, 401, { 'www-authenticate': 'Bearer' });
    }
    req.auth = { token: '', clientId: result.caller, scopes: [], extra: { caller: result } };
    void handle(req, res);
  });
  return { http, close: () => mcp.close() };
}
