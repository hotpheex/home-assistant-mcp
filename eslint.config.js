import { defineConfig } from 'eslint/config';
import tseslint from 'typescript-eslint';

// Only the gate reaches HA, and only the evaluator mints the Allowed the gate sends.
const GATE = 'src/gate.ts';
const EVALUATOR = 'src/evaluator.ts';
const gateOnly = 'Only src/gate.ts may reach Home Assistant.';
const haClientImport = {
  selector: "ImportExpression[source.value='home-assistant-js-websocket']",
  message: gateOnly,
};
const allowedCasts = ['TSAsExpression', 'TSTypeAssertion'].map((node) => ({
  selector: `${node}[typeAnnotation.typeName.name='Allowed']`,
  message: 'Only src/evaluator.ts may construct an Allowed.',
}));
const gateRules = {
  'no-restricted-imports': ['error', { paths: [{ name: 'home-assistant-js-websocket', message: gateOnly }] }],
  'no-restricted-globals': ['error', { name: 'fetch', message: gateOnly }],
  'no-restricted-properties': ['error', { object: 'globalThis', property: 'fetch', message: gateOnly }],
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
