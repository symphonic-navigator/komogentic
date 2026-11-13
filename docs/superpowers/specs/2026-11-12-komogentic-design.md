# Komogentic: an MCP gateway to Komodo, per user — Design

Date: 2026-11-12. Decided with Chris in a brainstorming session, after research into the existing Komodo MCP servers and into Kumbu² (`SCAI-NGO/kumbukumbu`), whose OAuth design and repository conventions this project takes over. "Decided by Chris" marks his decisions; "my call" marks choices made in the design that he can still overturn; everything else follows from those two or from the sources.

## 1. Why

Komodo (Core 2.3.4) runs a handful of applications on one VPS for a small team of three to four known users. Each user already has a Komodo account with their own rights: the maintainer is admin, everyone else has Execute and Logs on their own stacks. The team wants agents to operate those applications **under the account of the person they work for**: an assistant (Grok-based) that runs operations for a non-admin user, Claude Code for the maintainer, and later possibly an orchestrator.

What the agents must do well (decided by Chris):

- **Find faults from the logs**, up to "agentic deployment fixing": read the logs, find the cause, the fix goes through the repository and CI, then the agent deploys the new version.
- **See what runs and what is red** ("is it green?").
- **See deployments and trigger them**: deploy and restart.

The split is the principle (decided by Chris): **a push with a version tag builds the images; the MCP server triggers the deploy.** That leaves a clear point for a human in the loop. GitOps-style automation is later and not part of this server.

### Why not an existing server

Research on 2026-11-12 found four community MCP servers for Komodo:

- Three run with one fixed Komodo key for every caller, and their docs say that key is an admin's. That is a no-go (decided by Chris).
- `MP-Tool/komodo-mcp-server` 1.5.0 gets this right in principle: OAuth login with the user's Komodo password, a per-user Komodo JWT, and Komodo checks every call. But its sessions end after 1–2 hours (the access token lives 1 h, a hard limit of 2 h applies, there is no refresh for this login and tokens live only in memory). A non-admin also needs at least one specific permission on a resource (issue #217).

Building our own, small gateway was chosen over fixing that server upstream (decided by Chris; contributing upstream stays an option for later).

## 2. What the user sees

1. **Sign in to the dashboard with your Komodo username and password.** Komogentic has no user accounts of its own: Komodo is the only source of identity and rights (decided by Chris). All current users have local Komodo passwords and no second factor (no TOTP, no passkey), so the login is one step from username and password to a Komodo JWT. GitHub and OIDC login, and second factors, are not supported (§9).
2. **Create a connection**, as in Kumbu²: give it a name (e.g. "Grok assistant"), optionally an expiry (30, 90 or 365 days, or never). Komogentic shows the connection's **own MCP URL** (`{PublicUrl}/mcp/c/{id}`) with a copy button and short instructions per client.
3. **Add the URL as a custom connector** in the agent's app (Grok, claude.ai, ChatGPT web, …). The app sends the user to Komogentic's **consent page**: "**Grok** wants to use your connection **Grok assistant**: your Komodo stacks with your rights." Allow or Deny.
4. **For local agents** (Hermes and others that can't do MCP OAuth), create an **API key** instead: name, optional expiry, shown once, used as `Authorization: Bearer …` on plain `/mcp` (decided by Chris).
5. The dashboard lists connections and keys: name, MCP URL, client once authorised, created, last used, expiry, **Revoke**.

### End to end: a fault, found and fixed

1. A non-admin user, Anna, signs in to the dashboard with her Komodo username and password. Komogentic calls Komodo's local login, gets her JWT and opens a dashboard session.
2. She creates a connection "Grok assistant" (expiry 90 days). The dashboard shows `https://komogentic.example.org/mcp/c/q8m2x7` with instructions for Grok.
3. In the Grok app she adds a custom connector with that URL. Grok fetches `/.well-known/oauth-protected-resource/mcp/c/q8m2x7`, then the authorization server metadata, registers itself (DCR), and opens `/oauth/authorize?…&resource=https://komogentic.example.org/mcp/c/q8m2x7`. Komogentic stores the request and sends the browser to `/consent?request=…`; Anna is still signed in, sees "Grok wants to use your connection Grok assistant: your Komodo stacks with your rights", clicks **Allow**.
4. On Allow, Komogentic uses her JWT to create the Komodo API key `komogentic/Grok assistant` (expiry 90 days), issues the authorisation code, and on `/oauth/token` hands Grok an access and a refresh token. The Komodo secret is sealed under both tokens; the plain secret exists only in memory during this request.
5. Days later Anna writes to her assistant: "The app throws errors when I save a case, can you look?" The assistant calls `list_stacks` → `app` is **red**; `get_stack_status app` → service `backend` is restarting in a loop; `get_stack_logs app services=[backend] search=["exception"]` → a null reference in the save handler since the last deploy; `list_stack_updates app` → the deploy two hours ago succeeded with `:latest` of release 1.4.0.
6. The fix is made in the application's repository and released as 1.4.1 (tag → CI builds the images → `:latest` moves). This happens outside Komogentic.
7. Anna: "1.4.1 is out, please deploy." The assistant calls `deploy_stack app`; Grok asks Anna to confirm the call (the tool is marked as changing); she confirms. Komogentic unseals the Komodo secret with the access token, calls `DeployStack` as Anna, waits for the update, and returns "deploy succeeded in 48 s; app is green". Komodo shows Anna as the operator; Komogentic's audit log shows Anna, connection "Grok assistant", client "Grok", tool `deploy_stack`, stack `app`, success.
8. Had the assistant tried to deploy a stack Anna may only read, Komodo would have refused, and the tool would say "your Komodo user lacks Execute on stack X".

### The security boundary

- **Everything is security-relevant**, because the gateway holds credentials that can change running software: the OAuth server (`/oauth/*`, the well-known documents), the caller middleware, the session and consent API, the sealing of Komodo secrets, the Komodo client's authentication, and the choice of which Komodo calls exist at all.
- **What the gateway may call in Komodo** is a closed list: the read calls (`InspectImage` among them, added on 2026-11-13 by Chris, for the image versions of `get_stack_status`), `DeployStack`, `RestartStack` and `GetUpdate` from §4, plus the local login and creating and deleting the calling user's own API keys. No other Komodo request type appears in the code; a test enforces it (§8).
- **Not touched:** Komodo itself, its users, permissions, variables and configuration; the host's reverse proxy; other applications' stacks beyond the tools in §4.

### How rights work

- **Every connection and every API key owns exactly one Komodo API key of its user** (my call).
  - Komogentic creates it with the user's JWT from the dashboard session at the moment the first token that can seal it exists (my call): for an API key when the key is created, for a connection when the user clicks **Allow** on the consent page. Its secret is therefore never stored unsealed, not even between creating a connection and consenting.
  - It is named after the connection (e.g. `komogentic/Grok assistant`), and its expiry is that of the connection.
  - Komogentic stores the Komodo key's id (not secret) in the clear, so it can delete the key with the user's JWT later without needing the secret.
  - Komodo API keys act with their user's rights and don't expire unless told to. That is how the session towards Komodo stays alive: Komogentic never holds a Komodo JWT beyond the dashboard session.
- **Komodo decides where an agent may act; Komogentic decides what an agent can do at all.**
  - Komodo checks every call against the user's permissions, so an agent can never do more than its user.
  - Komogentic offers only the tools in §4. Stop, destroy, write and the other destructive or configuring operations don't exist in it, even where the user's Execute permission would allow them in Komodo (decided by Chris).
- **Two ways to cut an agent off, both immediate.** Revoke the connection in Komogentic; Komogentic then deletes the Komodo key. Or delete the key in Komodo; Komogentic then sees a 401 from Komodo and marks the connection dead.

## 3. Goals, non-goals, anti-goals

Goals:

- A custom connector added with only the URL reaches *Connected* in Grok and claude.ai, and the tools work.
- A connection keeps working without new sign-ins for as long as the client refreshes its tokens and the connection hasn't expired.
- An agent sees exactly the stacks its user sees in Komodo, and can deploy or restart exactly those its user may execute.
- `deploy_stack` reports the **outcome** (succeeded, failed and why), not just "started".
- API keys for local agents work alongside OAuth.

Non-goals (now):

- GitHub or OIDC login (users of those have no Komodo password; see §9).
- Komodo resources other than stacks: deployments, builds, repos, procedures, servers as targets.
- Admin features: managing Komodo users, permissions or variables.
- Orchestration across agents (a later project may build on this server).
- GitOps: syncs, resource files, config changes.

Anti-goals (a failure even if it works):

- Komogentic acting with more rights than the calling user, or with a shared or admin Komodo key.
- A second permission system next to Komodo's.
- Komodo API secrets, tokens or passwords in logs, URLs or browser storage, or readable from a database dump alone.
- A destructive operation reachable through Komogentic.
- A connection that silently stops working without the dashboard showing why.

## 4. The tools

Six tools, stacks only (decided by Chris: deploy and restart, nothing destructive, no pull because `DeployStack` pulls the images itself). Names and parameters are my call.

| Tool | What it does | Komodo calls (to verify against 2.3.4) | Annotations |
|---|---|---|---|
| `list_stacks` | Every stack the user can see: name, server, state, the green/yellow/red verdict in one word. "Is everything green?" is this tool. | `ListStacks` | read-only |
| `get_stack_status` | One stack: the verdict and why, per service: container state, health, image, update available and the image the compose file names now. Best effort (decided by Chris, 2026-11-13): the image's short id, and its version from the `org.opencontainers.image.version` label, so that an agent can tell which build runs behind `:latest`. The version needs Read on the server (Komodo's rule for `InspectImage`), and is left out without it, for a Swarm stack, or when the label is missing or doesn't look like a version. | `GetStack`, `ListStackServices`, `InspectImage` per distinct image id | read-only |
| `get_stack_logs` | Recent log lines of a stack, all services or chosen ones; `tail` (default 200, max 5000), timestamps; with `search` terms (and/or, case-insensitive), matching lines instead. | `GetStackLog`, `SearchStackLog` | read-only |
| `list_stack_updates` | The last operations on a stack (default 10): operation (deploy, restart, …), who started it, start and end, success. With an update id, that update's logs. Answers "what was deployed when, and did it work?" | `ListUpdates` filtered by target, `GetUpdate` | read-only |
| `deploy_stack` | Deploys a stack, or chosen services of it. Waits for Komodo's update to finish (up to a timeout, default 10 min), then returns success or failure with the relevant part of the update log, and the new verdict. | `DeployStack`, then `GetUpdate` until complete | not read-only, not destructive, not idempotent |
| `restart_stack` | Restarts a stack, or chosen services; waits and reports like `deploy_stack`. | `RestartStack`, then `GetUpdate` | not read-only, not destructive |

- **How a deploy reaches a new version (decided by Chris):**
  - Stacks follow a moving image tag, `:latest`, which moves only on a release tag (§7). `deploy_stack` therefore needs no version parameter: Komodo's `DeployStack` pulls the images the compose file names and brings the stack up.
  - Stacks whose compose files come from a Git repository (and, later, those managed GitOps-style) deploy through the same `DeployStack` call: Komodo pulls the repository, then the images. A version pinned in such a repository is changed by a commit there, never through Komogentic.
  - A stack that pins a version in Komodo's own configuration can still be redeployed and restarted, but Komogentic can't move it to another version. The README says so. Pre-releases (`-pre.N`) don't reach `:latest`, so an agent can't deploy them unless the stack follows such a tag.
  - Stacks with Komodo's poll and auto-update on deploy a new `:latest` by themselves; `deploy_stack` then still serves as a manual redeploy.
- **Stacks are named by their Komodo name**; ids are accepted too. An unknown or invisible stack gets the same answer ("no such stack"), so an agent can't probe for stacks it may not see.
- **Deploy and restart carry `readOnlyHint: false`,** so clients that ask before changing tools (Claude, Grok) ask the user. That is where the human in the loop sits (decided by Chris in spirit; the annotations are my call).
- **If the wait times out,** the tool says the operation is still running and gives the update id for `list_stack_updates`.
- **The verdict (my call; the builder may refine it with what Komodo reports):**
  - **Green:** the stack is running, and every service's container is running and not unhealthy.
  - **Yellow:** the stack is deploying or restarting, or a service is starting or reports no health yet.
  - **Red:** anything else: down, stopped, exited, unhealthy, restarting in a loop, unknown.
  - "Update available" is shown but doesn't change the colour.
- **Error messages are written for an agent:** what failed, what Komodo said, what to try. A Komodo 403 reads "your Komodo user lacks Execute on stack X", not a stack trace.

## 5. The protocol, taken from Kumbu²

Komogentic implements the OAuth side exactly as Kumbu² does (`src/Kumbu.Server/OAuth/`, `Auth/CallerMiddleware.cs`, design `docs/superpowers/specs/2026-10-25-oauth-connectors-design.md`, research `docs/notes-oauth-research.md`). Code may be copied freely: both projects are AGPL-3.0-or-later under the same maintainer (decided by Chris). What carries over unchanged:

- **One protected resource per connection** at `/mcp/c/{id}`, with protected resource metadata at `/.well-known/oauth-protected-resource/mcp/c/{id}` (404 for unknown ids). Plain `/mcp` accepts only API keys and has no OAuth metadata.
- **A real HTTP 401** with `WWW-Authenticate: Bearer resource_metadata=…, scope=…` from a middleware, not the SDK's `[Authorize]` (which yields 200 with a JSON-RPC error and never starts a sign-in).
- **Authorization server metadata** at `/.well-known/oauth-authorization-server`:
  - `code` only, `authorization_code` and `refresh_token`, S256 only, auth method `none`
  - `client_id_metadata_document_supported: true`, `iss` in the redirect
- **Client ID Metadata Documents** (with Kumbu²'s SSRF guards) and **Dynamic Client Registration** (public clients only, rate-limited, unused registrations expire after 24 h).
- **`/oauth/authorize` is anonymous and doesn't read the session cookie.** It validates the request, keeps it server-side for 10 min and sends the browser to the SPA's `/consent?request={id}`; the consent page's same-site fetch carries the cookie. This works around the SameSite=Strict cookie that cross-site navigation drops.
- **`/oauth/token`:**
  - Codes are single-use and live 60 s.
  - Access tokens live 60 min (configurable).
  - Refresh tokens rotate on every use, with a 30 s grace period that returns the same pair to a retry.
  - Reuse after the grace period revokes the whole token family.
  - Rate limits apply per client and network: all of Anthropic's traffic comes from one range.
- **`/oauth/revoke`** (RFC 7009).
- **Opaque tokens** with prefixes (`kgt_at_`, `kgt_rt_`, `kgt_ac_`, `kgt_` for API keys; my call), 32 random bytes in Base62, stored only as an HKDF lookup.
- **Scopes are hints** (`komodo:read`, `komodo:operate`). The rights are the user's in Komodo; a client that asks for read only gets the read-only tools only (my call, mirrors Kumbu²'s "read caps the grant").
- **Every client quirk Kumbu² has worked around:**
  - claude.ai: CIMD only with `none` in the auth methods; unknown grants ignored; canonical `resource`; one egress range; its timeouts.
  - ChatGPT web: needs DCR. ChatGPT desktop: an API key as a custom header.
  - Grok (the Grok app's custom connectors): connects with OAuth like claude.ai, no extra step (Kumbu²'s README; Chris has run it in practice). The assistant mentioned in §1 is such a Grok app setup, not a custom program on the xAI API.
  - The C# SDK's client asks for `client_secret_post` at DCR.
  - `WithTools([typeof(X)])`, not `WithTools(typeof(X))`.
  - Both MCP handshakes (2025-11-25 and 2026-07-28).

### What is different from Kumbu²

- **There are no user accounts and no passwords to store.**
  - Sign-in sends username and password to Komodo's local login and keeps the returned JWT for the length of the dashboard session; the password itself is never stored.
  - Komogentic needs no Argon2 for passwords. It does rate-limit sign-in attempts per IP (as Kumbu²'s wrong-key limiter), so it can't be used to guess Komodo passwords.
- **The dashboard session can't outlive the Komodo JWT inside it.**
  - The session cookie is set up as in Kumbu² (HttpOnly, Secure, SameSite=Strict, only under `/api`, an `Origin` check on POST).
  - The session ends at the earlier of its own limit and the JWT's expiry, after which the user signs in again.
  - The session is needed only to manage connections and to consent, never by agents.
- **The stored secret is a Komodo API secret, not a vault key.**
  - Like Kumbu²'s grants, it is sealed with AES-256-GCM under a key derived from each token that may use it: the access token, the refresh token and the API key. A database dump alone opens nothing.
  - On refresh, the old refresh token unseals it and the new pair seals it again.
  - If every token of a connection is lost (a revoked token family, an expired refresh token, a client that lost its tokens), the secret is gone with them. The connection then shows **needs reconnect** in the dashboard, as in Kumbu² (my call). A reconnect through the same URL leads to consent again; on Allow, Komogentic creates a new Komodo key and deletes the old one by its id with the user's JWT.
  - Komodo keys whose connection or API key is revoked or dead are deleted with the JWT of the next dashboard session or consent of that user (a "pending deletion" list per user). Until then they are useless, since nobody holds their secret, and recognisable by their `komogentic/` name prefix.
  - A connection that has expired, or that the user revoked, cannot be reconnected; the user creates a new one.
- **There is far less storage logic.** There are no vaults, slots, memberships or rekeying. One record per token or key holds the lookup, user, connection, client, scope, resource, expiry, family, used and revoked times, and the sealed secret. Kumbu²'s `OAuthTokens.cs` and `ApiKeys.cs` are a reference for the rotation and reuse logic, not for copying: they are tied to Kumbu²'s encryption.

## 6. Architecture

- **Server:** C# on .NET 10, ASP.NET Core minimal APIs, `ModelContextProtocol.AspNetCore` (the version Kumbu² uses or newer), stateless Streamable HTTP. One project for the host and one for the Komodo client and tools, or a single project if that stays clear (builder's call).
- **Komodo client:**
  - A small, typed HTTP client of Komodo's API: `POST /read`, `/execute`, `/auth` and so on with `{ "type": …, "params": … }`.
  - Requests are authenticated with `X-Api-Key` and `X-Api-Secret`, or with the JWT for the dashboard's calls.
  - Only the calls in §4 and those for login and for creating and deleting API keys (`CreateApiKey` and `DeleteApiKey` of the calling user, in `mogh_auth_client`'s manage API in 2.x).
  - The exact endpoint paths and response shapes are to be verified against Komodo 2.3.4. Note that Komodo serialises a permission without specifics as a bare string (MP-Tool #217).
- **Storage:**
  - MongoDB, as in Kumbu², with TTL indexes for expired records (my call: Chris prefers MongoDB, and it lets Kumbu²'s patterns carry over).
  - Whether it needs a replica set for transactions is the builder's call: with one record per token, atomic single-document updates may be enough.
- **Web app:** React, Vite, TypeScript, TanStack Query, pnpm, built into the server's `wwwroot`, as in Kumbu².
  - It has three pages: sign-in, connections and keys, and consent.
  - TypeScript rather than JSX, to match Kumbu² and its reusable consent page (my call).
- **Caller per request:** a middleware resolves the bearer on `/mcp/c/{id}` (access tokens only) or `/mcp` (API keys only) into a scoped caller holding the user, the connection and an authenticated Komodo client; tools take the client from DI and never see a token. Everything under `/mcp` and `/api` fails closed.
- **Audit:**
  - Komodo already records the user as the operator of each deploy and restart.
  - Komogentic additionally logs every tool call with user, connection, client, tool, stack and outcome, without secrets. This is what tells "the user by hand" from "the user's assistant".
- **Health:** `/healthz`, for Komodo and the reverse proxy.

## 7. Repository, CI/CD and versioning: as in Kumbu²

Decided by Chris: the ground rules, CI/CD and versioning of Kumbu² are taken over, adapted only where the projects differ.

- **`CLAUDE.md`:**
  - British English; match the surrounding code; comments only where the reasoning isn't obvious; an SPDX header `// SPDX-License-Identifier: AGPL-3.0-or-later` in source files.
  - The repository names no organisation, customer, employer, person or host. Deployment-specific settings go into `.env` or `compose.override.yaml`.
  - A branch per change, a pull request, squash merge; imperative free-form commit messages.
  - Specs go to `docs/superpowers/specs/`, plans to `docs/superpowers/plans/`.
  - It also records the release steps and the Dependabot note.
- **Build settings:** `Directory.Build.props` (net10.0, nullable, warnings as errors, `RestorePackagesWithLockFile`), `global.json`, `.editorconfig`, `packages.lock.json` per project, restored in locked mode in CI and the Dockerfile.
- **`ci.yml`:** server tests and web tests and build, on pull requests and `master`, actions pinned to commit hashes. No sharding until the test suite needs it.
- **`docker.yml`:**
  - One image, `ghcr.io/symphonic-navigator/komogentic`. The version comes from `version.txt`, giving `X.Y.Z-pre.N` on `master` and `X.Y.Z` from the tag.
  - Tags: branch, PR, semver and sha. `:latest` moves **only** on a `vX.Y.Z` tag without a `-`.
  - Images are signed with cosign 3.
- **Releasing:** a version in `version.txt`, the server's `<Version>` and `web/package.json`; a pull request "Release vX.Y.Z"; an annotated tag on the merge commit. No GitHub release objects. Pre-releases are tagged `vX.Y.Z-pre.N`.
- **`CHANGELOG.md`** in Kumbu²'s style (what changed for users and operators, per release). Dependabot for actions, Docker, Compose, NuGet and npm, as Kumbu²'s `dependabot.yml`.
- **Docker and Compose:**
  - A multi-stage, digest-pinned `Dockerfile` (node → dotnet sdk → aspnet), non-root, port 8080.
  - `compose.yaml` runs Komogentic and MongoDB. A Traefik variant is included if it fits the host's proxy, otherwise documented.
  - Deployed by Komodo itself, following `:latest`.
- **Configuration:**
  - `.envrc`, `.env.example` and a README table of every variable.
  - Variables include the public URL, the Komodo URL (reachable from the container, internal network preferred), the MongoDB connection, the access-token lifetime and the log level.
- **Docs:** `README.md` (what it is, prerequisites, installation, the Komodo permissions a user needs, connecting per client, development), and an `obsidian/` vault.
- **Version** starts at 0.1.0 (my call).

## 8. Tests

As in Kumbu²: xUnit v3, `WebApplicationFactory`, Testcontainers MongoDB, `FakeTimeProvider`, and the MCP SDK's own client for end-to-end flows.

- **The OAuth tests are taken over with the code they test:** discovery, registration, CIMD, authorize, token, refresh (grace period, parallel refreshes, reuse), revocation.
- **Komodo is faked at the HTTP boundary** in tests: a small fake Core that answers the calls of §4 with recorded shapes from 2.3.4, including errors (403, 401 for a deleted key, a failed deploy, a timeout).
- **The anti-goals get tests of their own:**
  - No tool reaches a destructive Komodo call.
  - A token for connection A doesn't work on connection B's URL.
  - An API key doesn't work on `/mcp/c/{id}`, and an access token doesn't work on `/mcp`.
  - Nothing secret appears in the logs.
  - A deleted Komodo key marks the connection dead.
- **The real clients are tested by hand,** following a short playbook in `docs/`, against the deployed instance: Grok, claude.ai, Claude Code with an API key, Hermes with an API key.

## 9. Later, not now

- **GitHub or OIDC users, and users with a second factor (TOTP, passkey) in Komodo.**
  - The way out is simple: the user creates a Komodo API key in Komodo's UI and pastes it into the dashboard when creating a connection.
  - That works for every login method. Signing in to the dashboard would then need another way too.
- **More tools,** if real use asks for them: deployments (as opposed to stacks), a build's status, server health.
- **Contributing longer sessions to `MP-Tool/komodo-mcp-server`,** if this project's approach proves itself.
- **Orchestration** by a later project, through this server's tools.

## 10. Left to the builder

- Project layout, class names, how much of Kumbu²'s code is copied as is versus adapted.
- Exact Komodo endpoints and response shapes in 2.3.4 (verify against the live instance or `moghtech/komodo` at the matching tag).
- Whether MongoDB needs a replica set.
- Refinements to the verdict from what Komodo actually reports for health.
- Log tail defaults, the wait timeout and how update logs are trimmed for an agent.
