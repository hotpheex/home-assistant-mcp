# Security

## Reporting a vulnerability

Report it privately through GitHub's private vulnerability reporting: [open a draft advisory](https://github.com/hotpheex/home-assistant-mcp/security/advisories/new) (Security tab, "Report a vulnerability"). Do not open a public issue.

Only the newest release gets fixes.

## Threat model

The server bounds a Caller that tries to do more than its job needs: a confused or prompt-injected agent, or a client given a too-broad tool. Its Grants are the bound. Confirming an individual call is the job of the Caller's harness, not the server.

A key the agent itself can read, such as an environment variable in its own shell, lets the agent call the server directly and skip its harness's confirmation prompt. For such a Caller the Grant is the only bound, so keep its write Grants narrow.

The server does not protect against an HA admin, against someone who controls the server's host or process (it holds the HA tokens, the admin token included), or against one entity's data reaching a reader: reads cover the whole house.

Every request is authenticated on its own. A missing, malformed, unknown or expired key gets the same 401. To rotate a key, add the new hash and restart, move the Caller to the new key, then remove the old hash and restart.

The server speaks plain HTTP. A key sent in clear can be replayed by anyone who sees it, so terminate TLS in front of the server or keep it on a private network, and use an `https://` HA URL when HA is across a network.

## What each Grant reveals and allows

| Grant | Tools | Gives |
|---|---|---|
| `read: plain` | `ha_get_states`, `ha_get_history`, `ha_get_logbook`, `ha_get_registry`, `ha_list_services` | States, history, logbook, registries and the service list of the **whole house**, at the users tier. |
| `read: config` | `ha_get_config`, `ha_list_traces`, `ha_get_trace` | The config and traces of every automation and script, at the admin tier. It does not include plain read: a trace call reads the entity registry only to refuse an id that names no automation or script, and returns nothing from it. |
| `services: [...]` | `ha_call_service`, plus plain read | The named services over the covered targets, at the users tier, with the service's response. |
| `config_write: <kind>` | `ha_write_config`, plus config read and plain read | Create, update and delete items of that kind, at the admin tier. Also the scene or helper config of that kind. |

**Plain read is not scoped.** Any Caller that can read sees every entity: every person's and device tracker's location, every camera entity, and every logbook entry. Bearer tokens in camera, image and media_player attributes are stripped, so a Caller gets no URL that opens their images or streams.

**A config write is full control of the house.** An automation or script can call any service, so a Caller that writes them can do anything HA can do. Grant it as you would an HA admin account.

Running a script or triggering an automation is an ordinary service Grant, and it grants everything that script or automation does. Service calls run with the users-tier token, so HA itself refuses admin-only services. No tool edits areas, labels or registry names, so a Caller cannot move an entity into its own Grant.

## How a service call is checked

HA expands the call's target (entity, device, area, floor or label ids, or `entity_id: all`) exactly as it would to run the call; target keys inside `data` count as part of the target. Entities whose domain the service does not act on are left out, so a `light` Grant serves `light.turn_on` on an area that also holds a switch, but an entity_id named outright outside those domains is refused. The call runs only if a Grant naming the service covers every remaining entity and no Deny reaches any of them. Otherwise the whole call is refused. HA then receives exactly the checked entity_id list.

An area or label matches what HA's own target of that area or label acts on:

- An entity is in an area if its own area is that area, or if it has no area and its device is in that area.
- A label reaches labelled entities, labelled devices with their child devices, and labelled areas.
- Hidden entities are in no area and no label.
- Config and diagnostic entities are reached only by a direct label, except that a Deny's area or label also reaches them.

`domain` and `*` match by entity_id prefix. To select one entity, give it a label in HA and grant the label. A service that declares no target is checked by name alone, and a call that sends it a target is refused.

`homeassistant.*` services and `scene.apply` act on whatever their data names, so a Grant must name each one exactly; a Grant's `<domain>.*` never reaches them, but a Deny's `scene.*` does reach `scene.apply`. A Deny applies to service calls only; reads and config writes cannot be denied.

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
- `test/serve.test.ts`: in the coverage matrix, config read and config write reach HA with the admin token only, and every other tool with the users-tier token only.
- `test/startup.test.ts`: exit on an admin users-tier token, and an unneeded admin token is never used.
- `test/e2e.test.ts`: a real HA admin's token is refused at startup.

**Target coverage.** A service call runs only if a Grant covers every entity of HA's own expansion of its target and no Deny reaches any of them; otherwise the whole call is refused. Target keys in service data join the target, and HA receives only the checked entity_id list.
- `test/evaluator.test.ts`: properties over generated Policies: a Deny always wins, one uncovered entity refuses the call, and adding a Grant never turns an allow into a deny.
- `test/path.test.ts`: generated houses, Policies and calls run through the real server, and an independent oracle judges every call HA receives.
- `test/services.test.ts`: area and label expansion, the service's domain filter, data-key merging, `entity_id: all`, delegating services and Denies on config entities.
- `test/e2e.test.ts`: against real HA, child devices under a label, hidden and config entities outside an area, and an area Deny catching a config button.

**Redaction.** Every read strips `access_token` attributes and `token=` URL parameters from camera, image and media_player states. Every read, plain, config and trace, masks values under secret-looking keys, URL userinfo and `Bearer` tokens, so a harmless value under a secret-looking key is masked too. A config write carrying the mask marker is refused, so a masked secret is never written back.
- `test/redaction.test.ts`: what is stripped and masked, and the expected leaks.
- `test/read.test.ts`, `test/config.test.ts` and `test/write.test.ts`: Redaction in the read tools, and the marker refusal.
- `test/e2e.test.ts`: no bearer token or secret from a real HA appears in any byte the ten tools return.

**Size cap.** A result is at most 48,000 characters, below Claude Code's 50,000-character file threshold, so a Caller never reasons over a saved file or a preview. A larger read is refused whole, with a hint that names the narrowing the tool offers. A larger write result is cut with a marker, because the write has already run.
- `test/read.test.ts`: a read at the cap returned whole, and one character over refused with the tool's narrowing.
- `test/services.test.ts`: an oversize service response cut with a marker.

**Audit.** The server writes one JSON object per line to stdout; audit records carry `"audit": true`. Every refusal is recorded, failed authentication included. Allowed calls are recorded only with `HAMCP_AUDIT_WRITES` or `HAMCP_AUDIT_READS`. An allowed write records `allow` before any request to HA and `outcome: done` once HA accepts it, so an `allow` with no `done` is a write that failed or whose outcome is unknown. Records hold names only: never service data, config bodies, responses or keys.
- `test/serve.test.ts`: refused keys and Origins audited without the key, and in the coverage matrix, every refused tool call audited and allowed calls audited only on opt-in.
- `test/services.test.ts` and `test/write.test.ts`: allowed writes audited by name before any request to HA, and their outcome once HA accepts them.

## Kill switch

Use the first stop that is fast enough, in this order:

1. **Stop the server.** Every Caller loses access at once.
2. **Revoke the server's HA tokens** in HA. Its connections close and the server exits; it cannot start again until you give it a valid token.
3. **Remove one Caller's key hash** from the Policy and restart.
4. **Remove the write Grants** from the Policy and restart.

> **Warning.** An invalid Policy makes the server exit at startup. Under a rolling update the new instance never becomes ready, and the old one keeps serving the old Policy, so the key you meant to revoke still works. In an emergency, stop the server first. Run `check` on the new Policy before any revocation deploy.

## Residual risks

These are accepted and documented, not fixed:

- **Redaction misses.** A secret under an innocuous key or in another string shape passes through. `test/redaction.test.ts` lists the known misses as expected leaks. Treat Redaction as hygiene, not a boundary.
- **HA response shapes are not validated.** If HA renamed `area_id`, an area Grant could widen. If it renamed `is_admin`, an admin token could pass the users-tier check. Only the weekly run against HA beta would catch either.
- **Config writes are admin-equivalent.** An automation or script can call any service, so a config-write Grant is full control of the house.
- **Policy meaning follows HA's target expansion.** An HA upgrade that changes how HA expands a target changes what an area or label selector covers.
- **Hidden entities escape area and label Denies.** HA puts a hidden entity in no area or label, so a domain Grant with an area Deny still reaches a hidden entity in that area.
- **Groups and data-field entities ride on the Grant.** The server checks the target only. It does not expand groups or check entities named in other service data fields.
- **Failed-auth log flooding.** Every failed authentication writes an audit line, and the server does not rate-limit. Rate-limit at the proxy.
- **The process holds the admin token** next to network-facing code.
