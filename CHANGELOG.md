# Changelog

What changed for the people who use and run Komogentic, per release.

## 0.1.0 (unreleased)

The first version.

### New

- **Agents operate Komodo stacks as the person they work for.** Six tools: `list_stacks` (with a green, yellow or red verdict per stack), `get_stack_status`, `get_stack_logs` (tail or search), `list_stack_updates`, `deploy_stack` and `restart_stack` (they wait for Komodo's update and report the outcome). Nothing destructive or configuring is reachable.
- **Sign in with your Komodo username and password.** No accounts of Komogentic's own; users with a second factor and GitHub or OIDC users can't sign in yet.
- **Connections for apps with MCP OAuth** (Grok, claude.ai, ChatGPT web): one URL per connection, a consent page, tokens that refresh for as long as the connection lives (30, 90 or 365 days, or never).
- **API keys for local agents** (Claude Code, Hermes, ChatGPT desktop), shown once.
- **Each connection and API key owns one Komodo API key** of its user, named `komogentic/<name>`; revoking deletes it, and a key deleted in Komodo shows the connection as needing a reconnect.
- **An audit line per tool call** in the log: user, connection or key, app, tool, stack, outcome.
- **Deployment:** one image, `ghcr.io/symphonic-navigator/komogentic`, signed with cosign; Compose with MongoDB, and optionally Traefik.
