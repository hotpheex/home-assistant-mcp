# AGENTS.md

An MCP server that sits between AI agents and Home Assistant and authorizes every read and write against a deny-by-default Policy. It is a security boundary: when a change trades safety for convenience, stop and ask.

## Invariants

- **Only the gate reaches HA, and only on an evaluator-issued `Allowed`.** Lint and a runtime check enforce this; a lint error here means the design is wrong, so restructure rather than disable the rule or cast.
- **Refuse whole, never narrow.** A call the Policy does not fully cover is refused as a whole, and every refusal writes an audit line.
- **HA expands targets.** The server asks HA what a target covers and checks that answer, so Policy meaning tracks HA. Leave area, label and device expansion to HA rather than reimplementing it.
- **Two tiers.** Plain reads and service calls use the users-tier token; only config read and config write use the admin token.
- **Audit and logs carry names only**: never service data, config bodies, responses or keys.

## Code

- Node runs the TypeScript directly, with no build step, so only erasable syntax works (no `enum`, `namespace` or parameter properties).
- Dependencies are exact versions, and `npm test` fails on any runtime dependency outside its allowlist. Keep the runtime set small.
- npm's `min-release-age` holds back versions published in the last three days. Pin the newest version that passes and leave the guard alone.
- A comment says why the code is shaped as it is, in at most three lines.

## Tests

- `npm run lint`, `npm run typecheck` and `npm test` must pass. The real-HA tests (`test/e2e.test.ts`) skip locally and run in CI.
- Test behaviour through the real server against the fake HA, or through the evaluator's property tests; mock no internal module.
- Pin a fix with an assertion in the test that already drives its path.
- SECURITY.md names the tests that pin each guarantee. Keep those citations true when you move, rename or delete a test.

## Docs

README.md and SECURITY.md are the user-facing contract. Change them in the same PR as the behaviour they describe.
