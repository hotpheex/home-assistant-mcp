import { defineConfig } from 'eslint/config';
import tseslint from 'typescript-eslint';

// Only the gate reaches HA, and only the evaluator mints the Allowed the gate sends.
const GATE = 'src/gate.ts';
const EVALUATOR = 'src/evaluator.ts';
const gateOnly = 'Only src/gate.ts may reach Home Assistant.';
/** Every module that opens a connection; node:module and process.getBuiltinModule would load the rest unseen. */
const TRANSPORTS = ['home-assistant-js-websocket', 'undici', ...['net', 'tls', 'https', 'http2', 'module'].flatMap((m) => [m, `node:${m}`])];
const haClientImport = {
  selector: `ImportExpression[source.value=/^(${[...TRANSPORTS, 'http', 'node:http'].join('|')})$/]`,
  message: gateOnly,
};
const allowedCasts = ['TSAsExpression', 'TSTypeAssertion'].map((node) => ({
  selector: `${node}[typeAnnotation.typeName.name='Allowed']`,
  message: 'Only src/evaluator.ts may construct an Allowed.',
}));
// globalThis and global are restricted whole, since an alias of either reaches fetch unseen.
const gateRules = {
  'no-restricted-imports': 'off',
  '@typescript-eslint/no-restricted-imports': [
    'error',
    {
      paths: [
        ...TRANSPORTS.map((name) => ({ name, message: gateOnly, allowTypeImports: true })),
        // The listener needs node:http's server side; its client side reaches HA.
        ...['http', 'node:http'].map((name) => ({ name, message: gateOnly, allowImportNames: ['createServer', 'IncomingMessage', 'ServerResponse'] })),
      ],
    },
  ],
  'no-restricted-globals': ['error', ...['fetch', 'WebSocket', 'globalThis', 'global'].map((name) => ({ name, message: gateOnly }))],
  'no-restricted-properties': ['error', { object: 'process', property: 'getBuiltinModule', message: gateOnly }],
};

export default defineConfig(
  { ignores: ['node_modules/'] },
  tseslint.configs.recommendedTypeChecked,
  { languageOptions: { parserOptions: { projectService: true } } },
  { files: ['**/*.js'], extends: [tseslint.configs.disableTypeChecked] },
  {
    files: ['test/**/*.ts'],
    rules: {
      '@typescript-eslint/no-floating-promises': [
        'error',
        { allowForKnownSafeCalls: [{ from: 'package', package: 'node:test', name: ['test', 'suite'] }] },
      ],
    },
  },
  {
    files: ['src/**/*.ts'],
    ignores: [GATE, EVALUATOR],
    rules: { ...gateRules, 'no-restricted-syntax': ['error', haClientImport, ...allowedCasts] },
  },
  { files: [EVALUATOR], rules: { ...gateRules, 'no-restricted-syntax': ['error', haClientImport] } },
  { files: [GATE], rules: { 'no-restricted-syntax': ['error', ...allowedCasts] } },
);
