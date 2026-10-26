import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { ESLint } from 'eslint';

/** The whole runtime-dependency allowlist; any other direct runtime dependency fails CI. */
const RUNTIME_ALLOWLIST = [
  '@modelcontextprotocol/node',
  '@modelcontextprotocol/server',
  'home-assistant-js-websocket',
  'yaml',
  'zod',
];

test('direct runtime dependencies are exact versions from the allowlist', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as Record<
    string,
    Record<string, string> | undefined
  >;
  const runtime = { ...pkg.dependencies, ...pkg.optionalDependencies, ...pkg.peerDependencies };
  assert.deepEqual(
    Object.keys(runtime).filter((name) => !RUNTIME_ALLOWLIST.includes(name)),
    [],
  );
  for (const [name, version] of Object.entries(runtime)) assert.match(version, /^\d+\.\d+\.\d+$/, name);
});

const eslint = new ESLint();
async function ruleIds(code: string, filePath: string) {
  const [result] = await eslint.lintText(code, { filePath });
  return result?.messages.map((m) => m.ruleId) ?? [];
}

const reachesHa = [
  "import { createConnection } from 'home-assistant-js-websocket';\nexport { createConnection };\n",
  "export const ha = await import('home-assistant-js-websocket');\n",
  "export const r = await fetch('http://ha:8123/api/');\n",
  "export const r = await globalThis.fetch('http://ha:8123/api/');\n",
];

test('lint fails on any import of the HA client or any fetch outside the gate', async () => {
  for (const code of reachesHa) {
    const outside = await ruleIds(code, 'src/tools.ts');
    assert.ok(outside.length > 0 && outside.every((id) => id?.startsWith('no-restricted-')), code);
    assert.deepEqual(await ruleIds(code, 'src/gate.ts'), [], code);
  }
});

test('lint fails on minting an Allowed outside the evaluator', async () => {
  const code = "import type { Allowed } from './evaluator.ts';\nexport const a = {} as unknown as Allowed;\n";
  assert.ok((await ruleIds(code, 'src/tools.ts')).includes('no-restricted-syntax'));
  assert.ok(!(await ruleIds(code, 'src/evaluator.ts')).includes('no-restricted-syntax'));
});
