# Changelog

What changed for the people who use and run Komogentic, per release.

## 0.1.1 (2026-11-13)

### Fixed

- **`get_stack_status` no longer shows a base image's version as the image's own.** `mongo:8` showed "version 24.04", Ubuntu's. A version now counts only when the image also names its source or revision, as images from a build pipeline do.
- **`get_stack_status` no longer names a compose file's image with variables in it** ("the compose file now names `${APP_IMAGE:-…}`"): Komodo gives the file's text unresolved, which is no image.

## 0.1.0 (2026-11-13)

The first version.

### New

- **Agents operate Komodo stacks as the person they work for.** Six tools: `list_stacks` (with a green, yellow or red verdict per stack), `get_stack_status`, `get_stack_logs` (tail or search), `list_stack_updates`, `deploy_stack` and `restart_stack` (they wait for Komodo's update and report the outcome). Nothing destructive or configuring is reachable.
- **Sign in with your Komodo username and password.** No accounts of Komogentic's own; users with a second factor and GitHub or OIDC users can't sign in yet.
- **Connections for apps with MCP OAuth** (Grok, claude.ai, ChatGPT web): one URL per connection, a consent page, tokens that refresh for as long as the connection lives (30, 90 or 365 days, or never).
- **API keys for local agents** (Claude Code, Hermes, ChatGPT desktop), shown once.
- **Each connection and API key owns one Komodo API key** of its user, named `komogentic/<name>`; revoking deletes it, and a key deleted in Komodo shows the connection as needing a reconnect.
- **Which build runs behind `:latest`:** `get_stack_status` shows each service's image with its short id and its version (the image's `org.opencontainers.image.version` label), best effort: the version needs Read on the stack's server in Komodo. It also names the image the compose file names now, when that differs.
- **An audit line per tool call** in the log: user, connection or key, app, tool, stack, outcome.
- **Deployment:** one image, `ghcr.io/symphonic-navigator/komogentic`, signed with cosign, its version in the `org.opencontainers.image.version` label (`0.1.0-pre.N` for builds of `master`); Compose with MongoDB, and optionally Traefik.
