# Security

## Reporting a vulnerability

Report it privately through GitHub's private vulnerability reporting: [open a draft advisory](https://github.com/hotpheex/home-assistant-mcp/security/advisories/new) (Security tab, "Report a vulnerability"). Do not open a public issue.

Only the newest release gets fixes.

## Guarantees

Each guarantee names the tests that pin it. The suite runs on every pull request (`npm test`), and the real-HA tests run on every pull request against the minimum and the pinned-stable HA, and weekly against HA stable and beta.

**Default deny.** A Caller can do only what its Grants give. A tool whose kind the Caller lacks is not listed, and calling it anyway is refused and audited with nothing sent to HA. A service that no Grant of the Caller names is refused before any request to HA.
- `test/serve.test.ts`: the coverage matrix, every tool for a Caller holding and lacking its kind.
- `test/evaluator.test.ts`: the property that a Caller with no Grant is refused every service.
- `test/services.test.ts`: a service no Grant names, and a Deny without targets, refused before any outbound message.

**The gate.** `src/gate.ts` is the only code that reaches HA. It sends only what an `Allowed` decision permits, and only the evaluator can build an `Allowed`: the gate refuses any decision the evaluator did not issue, and an issued one cannot be changed. Read tools may send only an allowlist of read-only commands.
- `test/repo.test.ts`: lint fails on any import of the HA client or another network client, or any `fetch` or `WebSocket`, outside the gate, and on casting to `Allowed` outside the evaluator.
- `test/serve.test.ts`: a forged, spread or altered decision handed to the gate sends nothing.
- `test/serve.test.ts`: in the coverage matrix, a read tool sends only read-only commands, and startup sends nothing beyond name lookups.

**Tiers and the admin pin.** Only config read and config write run with the admin token. Plain read and service calls run with the users-tier token, so HA refuses admin-only services. The server exits if the users-tier token belongs to an HA admin, and never reads a token no Grant needs.
- `test/serve.test.ts`: the admin pin, and in the coverage matrix, each tool reaches HA with its tier's token only.
- `test/startup.test.ts`: exit on an admin users-tier token, and an unneeded admin token is never used.
- `test/e2e.test.ts`: a real HA admin's token is refused at startup.

**Target coverage.** A service call runs only if a Grant covers every entity of HA's own expansion of its target and no Deny reaches any of them; otherwise the whole call is refused. Target keys in service data join the target, and HA receives only the checked entity_id list.
- `test/evaluator.test.ts`: properties over generated Policies: a Deny always wins, one uncovered entity refuses the call, and adding a Grant never turns an allow into a deny.
- `test/path.test.ts`: generated houses, Policies and calls run through the real server, and an independent oracle judges every call HA receives.
- `test/services.test.ts`: area and label expansion, the service's domain filter, data-key merging, `entity_id: all`, delegating services and Denies on config entities.
- `test/e2e.test.ts`: against real HA, child devices under a label, hidden and config entities outside an area, and an area Deny catching a config button.

**Redaction.** Every read strips `access_token` attributes and `token=` URL parameters from camera, image and media_player states. Config and trace reads mask values under secret-looking keys, URL userinfo and `Bearer` tokens. A config write carrying the mask marker is refused, so a masked secret is never written back.
- `test/redaction.test.ts`: what is stripped and masked, and the expected leaks.
- `test/read.test.ts`, `test/config.test.ts` and `test/write.test.ts`: Redaction in the read tools, and the marker refusal.
- `test/e2e.test.ts`: no bearer token or secret from a real HA appears in any byte the ten tools return.

## Residual risks

These are accepted and documented, not fixed:

- **Redaction misses.** A secret under an innocuous key or in another string shape passes through. `test/redaction.test.ts` lists the known misses as expected leaks. Treat Redaction as hygiene, not a boundary.
- **HA response shapes are not validated.** If HA renamed `area_id`, an area Grant could widen. If it renamed `is_admin`, an admin token could pass the users-tier check. Only the weekly run against HA beta would catch either.
- **Config writes are admin-equivalent.** An automation or script can call any service, so a config-write Grant is full control of the house.
- **Policy meaning follows HA's `target.py`.** HA does the target expansion, so an HA upgrade that changes it changes what an area or label selector covers.
- **Hidden entities escape area and label Denies.** HA puts a hidden entity in no area or label, so a domain Grant with an area Deny still reaches a hidden entity in that area.
- **Groups and data-field entities ride on the Grant.** The server checks the target only. It does not expand groups or check entities named in other service data fields.
- **Failed-auth log flooding.** Every failed authentication writes an audit line, and the server does not rate-limit. Rate-limit at the proxy.
- **The process holds the admin token** next to network-facing code.
