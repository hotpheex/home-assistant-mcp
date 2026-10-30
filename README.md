# home-assistant-mcp

An MCP server that lets AI agents use Home Assistant, but only as far as you allow.

Home Assistant tokens carry no scope: any token can do anything its user can. This server sits between your agents and HA. It holds the HA tokens, gives each agent (a *Caller*) its own key, and checks every read and write against a deny-by-default Policy file before anything reaches HA.

- **Deny by default.** A Caller can do only what its Grants allow. A call the Policy does not fully cover is refused whole, never narrowed.
- **HA decides what a target means.** For each service call the server asks HA which entities the target covers, exactly as HA would run it, and checks every one.
- **Least privilege towards HA.** Reads and service calls use a non-admin HA user; only config reads and writes use an admin token.
- **Audited.** Every refusal is logged as a JSON line, and allowed calls can be too.
- **Redacted.** Every read masks values under secret-looking keys, URL credentials and `Bearer` tokens as `**REDACTED**`, and strips camera, image and media_player bearer tokens. This is best-effort: see [SECURITY.md](SECURITY.md).

Requires Home Assistant 2026.10 or newer.

## Quick start

1. Make a key for each Caller. The Caller gets the key; the Policy gets only its hash.

   ```sh
   docker run --rm ghcr.io/hotpheex/home-assistant-mcp:0.1.0 keygen
   ```

2. Write `policy.yaml`, then check it with the `check` command:

   ```yaml
   version: 1
   callers:
     assistant:
       keys:
         - sha256: <hash from keygen>
   grants:
     - caller: assistant
       read: plain
   ```

   ```sh
   docker run --rm -v "$PWD/policy.yaml:/policy.yaml:ro" ghcr.io/hotpheex/home-assistant-mcp:0.1.0 check /policy.yaml
   ```

3. In Home Assistant, create a user that is **not** an administrator, and create a long-lived access token on that user's profile page.

4. Run the server, preferably by a [verified](#verify-the-image) digest. The image runs as UID 65532, which must be able to read the mounted files.

   ```sh
   docker run -d --name hamcp --read-only -p 127.0.0.1:8080:8080 \
     -v "$PWD/policy.yaml:/policy.yaml:ro" \
     -v "$PWD/ha-users-token:/run/secrets/ha-users-token:ro" \
     -e HAMCP_POLICY=/policy.yaml \
     -e HAMCP_HA_URL=http://homeassistant.local:8123 \
     -e HAMCP_HA_USERS_TOKEN_FILE=/run/secrets/ha-users-token \
     ghcr.io/hotpheex/home-assistant-mcp:0.1.0
   ```

5. Point the Caller's MCP client at `http://<host>:8080/mcp` with its key. For Claude Code:

   ```sh
   claude mcp add --transport http home-assistant http://127.0.0.1:8080/mcp --header "Authorization: Bearer hamcp_..."
   ```

## Policy

The Policy is one YAML file, read at startup; restart to change it. It declares Callers and their key hashes, then Grants that add up and Denies that always win.

This voice assistant may read the house, switch lights anywhere except the nursery, and run the scripts labelled `voice_scripts`:

```yaml
version: 1
callers:
  voice:
    keys:
      - sha256: 9b2e...
        expires: 2027-01-31        # optional
grants:
  - caller: voice
    read: plain
  - caller: voice
    services: [light.*]
    targets:
      - domain: light
  - caller: voice
    services: [script.turn_on]
    targets:
      - label: voice_scripts
denies:
  - caller: voice
    services: [light.*]
    targets:
      - area: nursery
```

Each Grant gives one kind of access:

| Grant | Gives |
|---|---|
| `read: plain` | States, history, logbook, registries and the service list of the whole house. |
| `read: config` | The config and traces of every automation and script. |
| `services: [...]` with `targets` | Those services on entities in the named domains, areas (`area_id`) or labels (`label_id`). Omit `targets` for services that take none. Includes plain read. |
| `config_write: automation \| script \| scene \| helper` | Create, update and delete items of that kind (`helper` covers `input_*`, `counter`, `timer` and `schedule`). Includes both reads. |

Two Grants deserve care. Plain read is not scoped: a Caller that can read sees every entity, including people's locations. A config write is full control of the house, since an automation can call any service. [SECURITY.md](SECURITY.md) explains exactly what each Grant reveals and how calls are checked.

To get editor validation, point the YAML language server at the JSON Schema that each release publishes:

```yaml
# yaml-language-server: $schema=https://github.com/hotpheex/home-assistant-mcp/releases/download/v0.1.0/policy.schema.json
```

## Commands

- `serve` (the default) runs the server.
- `check <policy>` validates a Policy. If HA is configured, it also reports areas, labels, domains and services that HA does not know. Run it before every Policy deploy.
- `keygen` prints a new key and its hash.

## Settings

All settings are environment variables.

| Variable | Default | Meaning |
|---|---|---|
| `HAMCP_POLICY` | required | Path of the Policy file. |
| `HAMCP_HA_URL` | required | Home Assistant's base URL. |
| `HAMCP_HA_USERS_TOKEN[_FILE]` | | Token of a non-admin HA user, for reads and service calls. |
| `HAMCP_HA_ADMIN_TOKEN[_FILE]` | | Token of an HA admin. Needed only for `read: config` and `config_write` Grants. |
| `HAMCP_LISTEN` | `0.0.0.0:8080` | Listen address. |
| `HAMCP_ALLOWED_ORIGINS` | | Comma-separated browser origins allowed to call `/mcp`. |
| `HAMCP_AUDIT_WRITES` | `false` | Also log allowed writes. |
| `HAMCP_AUDIT_READS` | `false` | Also log allowed reads. |

The server reads only the tokens its Grants need. It refuses to start if the users token belongs to an admin.

It speaks plain HTTP, so put it behind a TLS-terminating proxy or on a private network. `/healthz` and `/readyz` serve health checks.

## Verify the image

Releases publish multi-arch images tagged `X.Y.Z` and `X.Y`, with signed build provenance and an SBOM. Verify a tag, then deploy by the digest:

```sh
gh attestation verify oci://ghcr.io/hotpheex/home-assistant-mcp:0.1.0 \
  --repo hotpheex/home-assistant-mcp \
  --signer-workflow hotpheex/home-assistant-mcp/.github/workflows/release.yml
```

## Security

Read [SECURITY.md](SECURITY.md) before you grant writes. It covers the threat model, what each Grant reveals, the kill switch, the known residual risks and how to report a vulnerability.
