# home-assistant-mcp

An MCP server that authorizes every Home Assistant read and write against a deny-by-default Policy.

Home Assistant tokens carry no scope, so this server decides what each MCP client (a *Caller*) may read and change. Each Caller authenticates with its own key. A Caller holds only what its Grants in the Policy file give it. The server holds the HA tokens and sends HA only the calls it allowed.

It needs Home Assistant 2026.10 or newer.

## Quick start

1. Make a key for each Caller. Give the key to the Caller and put only its hash in the Policy:

   ```sh
   docker run --rm ghcr.io/hotpheex/home-assistant-mcp:0.1.0 keygen
   # key: hamcp_...      (give this to the Caller)
   # sha256: 3f1c...     (put this in the Policy)
   ```

2. Write `policy.yaml`:

   ```yaml
   version: 1
   callers:
     assistant:
       keys:
         - sha256: <sha256 from keygen>
   grants:
     - caller: assistant
       read: plain
   ```

   Check it with `docker run --rm -v "$PWD/policy.yaml:/policy.yaml:ro" ghcr.io/hotpheex/home-assistant-mcp:0.1.0 check /policy.yaml`.

3. In Home Assistant, create a user that is **not** an administrator, sign in as that user, and create a long-lived access token on its profile page. This is the users-tier token.

4. [Verify the image](#verify-the-image), then run it by the digest you verified. The image runs as UID 65532, so that user must be able to read the mounted files:

   ```sh
   docker run -d --name hamcp --read-only -p 127.0.0.1:8080:8080 \
     -v "$PWD/policy.yaml:/policy.yaml:ro" \
     -v "$PWD/ha-users-token:/run/secrets/ha-users-token:ro" \
     -e HAMCP_POLICY=/policy.yaml \
     -e HAMCP_HA_URL=http://homeassistant.local:8123 \
     -e HAMCP_HA_USERS_TOKEN_FILE=/run/secrets/ha-users-token \
     ghcr.io/hotpheex/home-assistant-mcp@sha256:<digest>
   ```

5. Point the Caller's MCP client at `http://<host>:8080/mcp` (Streamable HTTP) and send the key as `Authorization: Bearer hamcp_...` on every request. For Claude Code:

   ```sh
   claude mcp add --transport http home-assistant http://127.0.0.1:8080/mcp --header "Authorization: Bearer hamcp_..."
   ```

The server serves both the current and the older MCP protocol, statelessly. It also serves `/healthz` (the process is up) and `/readyz` (every HA connection it needs is up). Both are unauthenticated and return only a status code.

## Verify the image

Releases publish `ghcr.io/hotpheex/home-assistant-mcp` for amd64 and arm64, tagged `X.Y.Z` and `X.Y` (there is no `latest`). Each image carries SLSA build provenance signed in the release workflow. Check it before you run a tag:

```sh
gh attestation verify oci://ghcr.io/hotpheex/home-assistant-mcp:0.1.0 \
  --repo hotpheex/home-assistant-mcp \
  --signer-workflow hotpheex/home-assistant-mcp/.github/workflows/release.yml
```

Then deploy by the digest it verified, not by the tag. The SBOM is attached to the image:

```sh
docker buildx imagetools inspect ghcr.io/hotpheex/home-assistant-mcp:0.1.0 --format '{{ json .SBOM }}'
```

The image runs as UID 65532 and works with a read-only root filesystem (`docker run --read-only`, or `readOnlyRootFilesystem: true` in Kubernetes).

## Settings

Settings come from environment variables only. The server reads them once at startup and exits non-zero if one is invalid.

| Variable | Default | Meaning |
|---|---|---|
| `HAMCP_POLICY` | required | Path of the Policy file. `--policy <path>` overrides it. |
| `HAMCP_HA_URL` | required | Home Assistant's base URL, `http://` or `https://`. |
| `HAMCP_HA_USERS_TOKEN` or `HAMCP_HA_USERS_TOKEN_FILE` | none | Long-lived token of a non-admin HA user. Needed if any Grant gives plain read, which every Grant except `read: config` does. |
| `HAMCP_HA_ADMIN_TOKEN` or `HAMCP_HA_ADMIN_TOKEN_FILE` | none | Long-lived token of an HA admin. Needed only if a Grant gives config read or a config write. |
| `HAMCP_LISTEN` | `0.0.0.0:8080` | Listen address, `<host>:<port>`. Write an IPv6 host in brackets. |
| `HAMCP_ALLOWED_ORIGINS` | empty | Comma-separated browser origins allowed to call `/mcp`. A request with any other `Origin` header gets 403. Non-browser MCP clients send no `Origin`. |
| `HAMCP_AUDIT_WRITES` | `false` | Also record allowed writes. |
| `HAMCP_AUDIT_READS` | `false` | Also record allowed reads. |

For each token, set the value or the `_FILE` path, not both. The server reads only the tokens its Grants need. It refuses to start if a needed token is missing, and warns about an admin token that no Grant needs. It exits if the users-tier token belongs to an HA admin, if HA rejects a token (also while running), or if HA is older than 2026.10. It warns, but serves, when HA is newer than the release it was tested with.

**TLS.** The server speaks plain HTTP. Terminate TLS at a reverse proxy in front of it, or keep it on a private network that only its Callers can reach. A key sent in clear can be replayed by anyone who sees it. Use an `https://` HA URL when HA is across a network.

**Logs.** The server writes one JSON object per line to stdout. Audit records carry `"audit": true`. Every denial is recorded, including failed authentication. Allowed calls are recorded only with the audit settings above. Records hold names only: never service data, config bodies, responses or keys.

## Commands

- `serve` (the default) runs the server.
- `check <policy>` validates a Policy with the same errors and warnings as startup and exits non-zero on an error. With `HAMCP_HA_URL` and a users-tier token set, it also resolves every area, label, domain and service against live HA and reports each unknown name as an error. Use it in CI and before every Policy deploy.
- `keygen` prints a new random `hamcp_` key and its SHA-256 hash.

## Policy

A Policy is one YAML 1.2 file, read once at startup. To change it, restart the server. Startup logs its SHA-256 digest as `policy_sha256`, so you can match the running Policy to a commit.

```yaml
version: 1                      # required
callers:
  <name>:
    keys:
      - sha256: <64 hex>        # from keygen
        expires: 2027-01-31     # optional; the key stops at 00:00 UTC on this date
grants:
  - caller: <name>
    read: plain | config
  - caller: <name>
    services: [<domain>.<service> | <domain>.*, ...]
    targets:                    # optional; omitted covers targetless services only
      - domain: <domain> | '*'
      - area: <area_id>
      - label: <label_id>
  - caller: <name>
    config_write: automation | script | scene | helper
denies:
  - caller: <name>
    services: [...]
    targets: [...]              # optional; omitted withholds the services entirely
```

**Rules.**

- Each Grant holds exactly one of `read`, `services` or `config_write`. Each target entry holds exactly one of `domain`, `area` or `label`.
- `area` and `label` take HA ids (`area_id`, `label_id`, such as `living_room`), not display names.
- A service is `<domain>.<service>` or `<domain>.*`. A bare `*` is an error.
- `homeassistant.*` services and `scene.apply` act on whatever their data names, so a Grant must name each one exactly. `homeassistant.*` is an error, and a Grant's `<domain>.*` never reaches them. A Deny's `scene.*` does reach `scene.apply`.
- `helper` covers `input_*`, `counter`, `timer` and `schedule`.
- Grants add up. A Deny wins over any Grant. A Deny applies to service calls only; reads and config writes cannot be denied.
- Errors refuse startup: an unknown field, a malformed key hash, a Grant or Deny naming an undeclared Caller, one key hash on two Callers, and a broken rule above.
- Warnings are logged, not refused: a Caller with no unexpired key, a Deny that overlaps no Grant, a key that expires within 14 days (also checked daily), and, once HA is reachable, an area, label, domain or service HA does not know. A call on an unknown name matches nothing.

**How a service call is checked.** HA expands the call's target (entity, device, area, floor or label ids, or `entity_id: all`) exactly as it would to run the call. The server asks HA for this on every call. Target keys inside `data` count as part of the target. Entities whose domain the service does not act on are left out, so a `light` Grant serves `light.turn_on` on an area that also holds a switch. An entity_id you name outright outside those domains is refused. The call runs only if a Grant naming the service covers every remaining entity and no Deny reaches any of them. Otherwise the whole call is refused, never narrowed. HA then receives exactly the checked entity_id list.

An area or label matches what HA's own target of that area or label acts on:

- An entity is in an area if its own area is that area, or if it has no area and its device is in that area.
- A label reaches labelled entities, labelled devices with their child devices, and labelled areas.
- Hidden entities are in no area and no label.
- Config and diagnostic entities are reached only by a direct label, except that a Deny's area or label also reaches them.

`domain` and `*` match by entity_id prefix. To select one entity, give it a label in HA and grant the label. A service that declares no target is checked by name alone, and a call that sends it a target is refused.

**Example.** A voice assistant may read the house, switch lights anywhere except the nursery, and run one script:

```yaml
version: 1
callers:
  voice:
    keys:
      - sha256: 9b2e...
grants:
  - caller: voice
    services: [light.*]
    targets:
      - domain: light
  - caller: voice
    services: [script.turn_on]
    targets:
      - label: voice_scripts      # label the scripts it may run
denies:
  - caller: voice
    services: [light.*]
    targets:
      - area: nursery
```

An automation author that writes automations and nothing else:

```yaml
grants:
  - caller: author
    config_write: automation
```

**Editor validation.** Each release publishes the Policy's JSON Schema as `policy.schema.json`. With the YAML language server (as in VS Code's YAML extension), add this first line to the Policy:

```yaml
# yaml-language-server: $schema=https://github.com/hotpheex/home-assistant-mcp/releases/download/v0.1.0/policy.schema.json
```

The schema checks fields and their shapes. Run `check` for the rules it cannot express, such as one kind per Grant and declared Callers.

## What each Grant reveals and allows

| Grant | Tools | Gives |
|---|---|---|
| `read: plain` | `ha_get_states`, `ha_get_history`, `ha_get_logbook`, `ha_get_registry`, `ha_list_services` | States, history, logbook, registries and the service list of the **whole house**, at the users tier. |
| `read: config` | `ha_get_config`, `ha_list_traces`, `ha_get_trace` | The config and traces of every automation and script, at the admin tier. It does not include plain read. |
| `services: [...]` | `ha_call_service`, plus plain read | The named services over the covered targets, at the users tier, with the service's response. |
| `config_write: <kind>` | `ha_write_config`, plus config read and plain read | Create, update and delete items of that kind, at the admin tier. Also the scene or helper config of that kind. |

Plain read is not scoped. Any Caller that can read sees every entity: every person's and device tracker's location, every camera entity, and every logbook entry. Bearer tokens in camera, image and media_player attributes are stripped, so a Caller gets no URL that opens their images or streams.

A config write is **full control of the house**. An automation or script can call any service, so a Caller that writes them can do anything HA can do. Grant it as you would an HA admin account.

Running a script or triggering an automation is an ordinary service Grant, and it grants everything that script or automation does. Groups and entities named in service data (other than target keys) are not expanded or checked: they ride on the Grant for the service.

A hidden entity is outside every area and label. An area or label Grant does not cover it, and an area or label Deny does not protect it. A domain Grant together with an area Deny still lets a Caller act on a hidden entity in that area.

Service calls run with the users-tier token, so HA itself refuses admin-only services. No tool edits areas, labels or registry names, so a Caller cannot move an entity into its own Grant.

## Threat model

The server bounds a Caller that tries to do more than its job needs: a confused or prompt-injected agent, or a client given a too-broad tool. Its Grants are the bound. Confirming an individual call is the job of the Caller's harness, not the server.

A key the agent itself can read, such as an environment variable in its own pod or shell, lets the agent call the server directly and skip its harness's confirmation prompt. For such a Caller the Grant is the only bound, so keep its write Grants narrow.

The server does not protect against an HA admin, against someone who controls the server's host or process (it holds the HA tokens, the admin token included), or against one entity's data reaching a reader: reads cover the whole house.

Every request is authenticated on its own, inside an open MCP session too. A missing, malformed, unknown or expired key gets the same 401. To rotate a key, add the new hash and restart, move the Caller to the new key, then remove the old hash and restart.

## Kill switch

Use the first stop that is fast enough, in this order:

1. **Stop the server.** Every Caller loses access at once.
2. **Revoke the server's HA tokens** in HA. Its connections close and the server exits; it cannot start again until you give it a valid token.
3. **Remove one Caller's key hash** from the Policy and restart.
4. **Remove the write Grants** from the Policy and restart.

> **Warning.** An invalid Policy makes the server exit at startup. Under a rolling update the new instance never becomes ready, and the old one keeps serving the old Policy, so the key you meant to revoke still works. In an emergency, stop the server first. Run `check` on the new Policy before any revocation deploy.

## Residual risks

These are accepted and documented, not fixed:

- **Redaction is best-effort.** Config and trace reads mask values under secret-looking keys, URL userinfo and `Bearer` tokens. A secret under another key or in another shape passes through.
- **HA's responses are not validated.** If HA renamed `area_id`, an area Grant could widen. If it renamed `is_admin`, an admin token could pass the users-tier check. Only the weekly run against HA beta would catch either.
- **A config write is full control of the house.**
- **Policy meaning follows HA's own target expansion** across HA upgrades, because HA does the expansion.
- **A hidden entity escapes area and label Denies.**
- **Groups and entities named in service data ride on the Grant.**
- **Failed authentication is not rate limited.** Each failure writes an audit line, so a prober can flood the log. Rate-limit at the proxy.
- **The process holds the admin token** next to network-facing code.

See [SECURITY.md](SECURITY.md) for the guarantees, the tests that pin them, and how to report a vulnerability.
