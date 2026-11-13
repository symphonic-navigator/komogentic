# Komogentic

An MCP gateway to [Komodo](https://github.com/moghtech/komodo): agents read logs, check what is green and what is red, and deploy or restart stacks, **each with the Komodo account and rights of the person it works for**.

- **Komodo is the only source of identity and rights.** You sign in to Komogentic's dashboard with your Komodo username and password. Komogentic has no users of its own and stores no password.
- **Every connection and every API key owns exactly one Komodo API key of its user**, named `komogentic/<name>`. Komodo checks every call against that user's permissions, so an agent never does more than its user.
- **Komogentic decides what an agent can do at all:** six tools for stacks. Stop, destroy, pull, write and every configuring call don't exist in it.
- **Two ways to cut an agent off, both immediate:** revoke it in Komogentic (which also deletes its Komodo key), or delete its Komodo key in Komodo.

Licence: AGPL-3.0-or-later.

## The tools

| Tool | What it does | Changes something |
|---|---|---|
| `list_stacks` | Every stack you can see: name, server, state and a verdict, `green`, `yellow` or `red`. "Is everything green?" is this tool. | no |
| `get_stack_status` | One stack: the verdict and why; per service the container state, health, image and whether an update is available. | no |
| `get_stack_logs` | Recent log lines (`tail`, default 200, at most 5000; `timestamps`), of all services or chosen ones. With `search` terms (any or all of them, case-insensitive, taken literally), the matching lines of the last 5000 instead. | no |
| `list_stack_updates` | The last operations on a stack (default 10): what, who, start, end, success. With `update_id`, that update's logs. | no |
| `deploy_stack` | Deploys a stack or chosen services, waits for Komodo's update (default 50 s, `wait_seconds` up to 600), then reports success or failure with the relevant log and the new verdict. | yes |
| `restart_stack` | Restarts a stack or chosen services; waits and reports like `deploy_stack`. | yes |

`deploy_stack` and `restart_stack` are marked as not read-only, so clients that ask before changing tools (Claude, Grok) ask you first. A stack is named by its Komodo name or id; a stack that doesn't exist and one you may not see get the same answer.

**The verdict:**

- **green**: the stack runs, and every service's container runs and isn't unhealthy;
- **yellow**: the stack is deploying, or a service is being created or its health check is still starting;
- **red**: anything else: down, stopped, paused, exited with an error, dead, unhealthy, restarting in a loop, unknown.

A service whose container exited with code 0 (a one-off job such as a migration) counts as completed, not red, and the services in the stack's `ignore_services` (Komodo's setting for init containers and the like) don't count at all. Compose files missing from the repository, or a compose project missing on the host while the stack should be up, make it red. "Update available" is shown but doesn't change the colour.

**Why the default wait is 50 s:** many MCP clients cut off a tool call after 60 s. When the wait ends first, the tool says the operation is still running and gives the update id, which `list_stack_updates` follows. Clients with longer limits (Claude Code) can pass a larger `wait_seconds`.

**How a deploy reaches a new version.** Stacks follow a moving image tag (`:latest`) that moves only on a release; `DeployStack` pulls the images the compose file names and brings the stack up, so `deploy_stack` needs no version. Stacks whose compose files come from a Git repository deploy the same way (Komodo pulls the repository first). What Komogentic can't do:

- move a stack that pins a version in Komodo's own configuration to another version (it can still redeploy and restart it);
- deploy a pre-release (`-pre.N`), which never reaches `:latest`, unless the stack follows such a tag.

**Swarm-mode stacks** use the same calls. Their verdict comes from Komodo's swarm state per service (`Healthy`, `Unhealthy`, `Down`) and **is untested** against a live swarm. Their logs can be read one service at a time only (Komodo's limit): pass exactly one service. They can't be searched: Komodo 2.3.4's `SearchStackLog` asks the swarm for the bare service name, which it doesn't know, so `get_stack_logs` refuses a search there and points to the tail.

## What a Komodo user needs

- A **local** Komodo login: a username and a password, **without a second factor** (no TOTP, no passkey). GitHub and OIDC users, and users with a second factor, can't sign in to Komogentic yet.
- **Read** on a stack to see it, its services and its updates.
- **Read with the Logs permission** on a stack to read its logs (Komodo asks for it on log calls); without it the log tools say so.
- **Execute** on a stack to deploy and restart it.
- Komodo's own limits apply. Note especially its **sign-in rate limit**: Komodo counts failed authentications per IP address (by default 5 in 15 s), and it sees all of Komogentic's requests coming from one address. Komogentic therefore limits sign-ins itself (3 a minute per username, 5 per address) and never retries a credential Komodo refused. If several people share a Komogentic, consider raising `KOMODO_AUTH_RATE_LIMIT_MAX_ATTEMPTS` in Komodo. The flip side of Komogentic's own limit: anyone can use up a known username's three attempts a minute, which delays that person's sign-in by a minute; it never exposes anything.

## Installation

Prerequisites: Docker with Compose, a Komodo Core 2.3.x Komogentic can reach, and for apps like claude.ai or Grok a public HTTPS address.

```sh
curl -fsSLO https://raw.githubusercontent.com/symphonic-navigator/komogentic/master/compose.yaml
curl -fsSLO https://raw.githubusercontent.com/symphonic-navigator/komogentic/master/.env.example
cp .env.example .env    # set KOMOGENTIC_KOMODO_URL and KOMOGENTIC_PUBLIC_URL
docker compose up -d
```

Komogentic then listens on `127.0.0.1:8080`, behind your reverse proxy. With Traefik on the same host, `compose.traefik.yaml` does the TLS and the routing:

```sh
docker compose -f compose.yaml -f compose.traefik.yaml up -d   # needs KOMOGENTIC_HOST in .env
```

Already running a Traefik? Copy the `komogentic` service's labels and networks from `compose.traefik.yaml` into a `compose.override.yaml` (the file's header explains it).

**Deployed by Komodo itself:** add the two Compose files as a stack in Komodo, following `:latest`, with the `.env` values as the stack's environment.

**Reaching Komodo:** prefer an internal Docker network between Komogentic and Komodo Core (put both on one network in a `compose.override.yaml` and use Komodo Core's container name in `KOMOGENTIC_KOMODO_URL`). Each request carries a Komodo API secret in its headers: plain `http` only on such an internal network.

**MongoDB** runs as a single-node replica set (`rs0`): Komogentic's token rotation and consent write several documents in one transaction. `compose.yaml` initiates it on the first start.

Images are signed with cosign 3:

```sh
cosign verify ghcr.io/symphonic-navigator/komogentic:latest \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/symphonic-navigator/komogentic/\.github/workflows/docker\.yml@'
```

## Configuration

`.env.example` lists every setting with a placeholder; `compose.yaml` passes them on as `Komogentic__…`.

| Variable | What it does | Format | Example |
|---|---|---|---|
| `KOMOGENTIC_KOMODO_URL` | Required. Where Komogentic reaches Komodo Core, from inside its container. | Absolute `http(s)` URL, no path | `http://komodo-core:9120` |
| `KOMOGENTIC_PUBLIC_URL` | Where people and apps reach Komogentic. Connection URLs, OAuth metadata and the dashboard's Origin check are built from it. Not used with `compose.traefik.yaml`. | Scheme, host and port, no path | `https://komogentic.example.org` |
| `KOMOGENTIC_KOMODO_TIMEOUT_SECONDS` | How long one Komodo request may take (default 30). | Seconds, 1–600 | `30` |
| `KOMOGENTIC_OAUTH_ACCESS_TOKEN_MINUTES` | Lifetime of an app connection's access token (default 60). Shorter means more refreshes. | Minutes, 5–1440 | `60` |
| `KOMOGENTIC_PORT` | Host port Komogentic is published on, on localhost only (default 8080). | Port | `8080` |
| `KOMOGENTIC_TRUSTED_PROXY` | `true` when a reverse proxy in front sets `X-Forwarded-For` and `X-Forwarded-Proto` and is the only way in. The rate limits then count the client's address. Never `true` with the port reachable from elsewhere. | `true` / `false` | `false` |
| `KOMOGENTIC_LOG_LEVEL` | Log level (default `Information`). | `Trace`, `Debug`, `Information`, `Warning`, `Error` | `Information` |
| `KOMOGENTIC_IMAGE` | The image to run (default `ghcr.io/symphonic-navigator/komogentic:latest`). | Image reference | `ghcr.io/symphonic-navigator/komogentic:0.1.0` |
| `KOMOGENTIC_MONGO_IMAGE` | The MongoDB image (default `mongo:8`). | Image reference | `mongo:8` |
| `KOMOGENTIC_HOST` | `compose.traefik.yaml` only: the host name, its DNS record pointing at this host. | Host name | `komogentic.example.org` |
| `KOMOGENTIC_ACME_EMAIL` | `compose.traefik.yaml` only: contact for Let's Encrypt's notices (optional). | E-mail address | `ops@komogentic.example.org` |
| `KOMOGENTIC_ACME_CA_SERVER` | `compose.traefik.yaml` only: the ACME server (default Let's Encrypt production). | URL | `https://acme-staging-v02.api.letsencrypt.org/directory` |
| `KOMOGENTIC_TRAEFIK_IMAGE` | `compose.traefik.yaml` only: the Traefik image (default `traefik:v3.7`). | Image reference | `traefik:v3.7` |
| `TZ` | Time zone of the log's timestamps (default `UTC`). | tz database name | `Europe/Berlin` |

## Connecting an agent

Sign in to the dashboard, then:

- **Grok, claude.ai, ChatGPT (web):** create a **connection** (a name, an expiry of 30, 90 or 365 days or never). Add its URL, `https://komogentic.example.org/mcp/c/<id>`, as a custom connector in the app. The app sends you to Komogentic's consent page: "**Grok** wants to use your connection **Grok assistant**: your Komodo stacks with your rights." Allow, and the app is connected for as long as it refreshes its tokens and the connection hasn't expired.
- **Claude Code, Hermes, ChatGPT desktop and other agents without MCP OAuth:** create an **API key**. It is shown once. Use it on the plain endpoint `https://komogentic.example.org/mcp` as `Authorization: Bearer kgt_…`:

  ```sh
  claude mcp add --transport http komogentic https://komogentic.example.org/mcp --header "Authorization: Bearer kgt_…"
  ```

An app that asks only for the scope `komodo:read` gets the four reading tools only. `docs/client-playbook.md` walks through each client and what to expect.

**When a connection shows "Needs reconnect":** its tokens are gone, because the app signed out, an old token was reused, or Komodo rejected its key (someone deleted it in Komodo). Add the same URL in the app again; on Allow, Komogentic creates a new Komodo key and deletes the old one. A revoked or expired connection can't be reconnected: create a new one.

## How Komogentic keeps secrets

- **Your password** goes to Komodo's local login once, at sign-in, and is never stored. The dashboard session keeps the Komodo JWT Komodo returns, sealed with AES-256-GCM under a key derived from the session cookie's secret. The session ends after 30 minutes idle, 12 hours at most, and never later than the JWT.
- **Each Komodo API secret** is sealed with AES-256-GCM under a key derived from each token that may use it: the connection's access and refresh tokens, or the API key. Tokens and keys are stored only as HKDF lookups. A database dump alone opens nothing.
- The session cookie is `HttpOnly`, `Secure`, `SameSite=Strict` and sent only to `/api`; every state-changing `/api` request must come from Komogentic's own pages (an `Origin` check).
- Komodo keys of revoked or dead credentials are deleted with the JWT of your next sign-in or consent; until then nobody holds their secret, and their `komogentic/` name prefix makes them easy to spot in Komodo.
- **Known limits, by design (as in Kumbu²):** an authorisation code that is presented again within 10 minutes of its expiry revokes the connection's tokens; later than that it is just refused. A refresh token of an older set, presented beside a newer one, also revokes the connection's tokens, so whoever holds a stale refresh token can force a reconnect, though never get in. If MongoDB fails at the very moment a Komodo key is being created and cleaned up again, the log names the key's id (never its secret) so it can be deleted by hand.
- Komodo records you as the operator of every deploy and restart. Komogentic's log adds, for every tool call, the user, the connection or key, the app, the tool, the stack and the outcome, without secrets.

## Development

```sh
docker run -d --name komogentic-test-mongo -p 27017:27017 mongo:8 --replSet rs0 --bind_ip_all
docker exec komogentic-test-mongo mongosh --quiet --eval 'rs.initiate({_id: "rs0", members: [{_id: 0, host: "127.0.0.1:27017"}]})'
export KOMOGENTIC_TEST_MONGO="mongodb://localhost:27017/?replicaSet=rs0&directConnection=true"

dotnet restore --locked-mode && dotnet build --configuration Release --no-restore
dotnet test --solution Komogentic.slnx --configuration Release --no-build
pnpm -C web install --frozen-lockfile && pnpm -C web test --run && pnpm -C web build
```

Without `KOMOGENTIC_TEST_MONGO` the tests start a MongoDB container themselves. The tests fake Komodo at the HTTP boundary; the real clients are tested by hand (`docs/client-playbook.md`).

To run the server locally: `dotnet run --project src/Komogentic.Server` with `Komogentic__Komodo__Url`, `Komogentic__Mongo__ConnectionString` and `Komogentic__PublicUrl=http://localhost:8080` set, and `pnpm -C web dev` for the web app (Vite proxies `/api`, `/mcp`, `/oauth` and `/.well-known` to port 8080). `CLAUDE.md` has the repository's rules; specs and plans are in `docs/superpowers/`.
