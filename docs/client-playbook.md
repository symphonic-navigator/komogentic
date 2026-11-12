# Client playbook

How to check, by hand and against the deployed instance, that the real clients work with Komogentic. The automated tests fake Komodo and use the MCP SDK's client; these steps cover what they can't: the apps themselves. `https://komogentic.example.org` stands for the instance, `app` for a stack the test user may execute, `other` for one the user may only read.

Before you start:

- A non-admin Komodo user with a local password and no second factor, Read and Execute on `app` (with the Logs permission), Read only on `other`.
- Sign in to `https://komogentic.example.org` as that user: the dashboard shows "Connections" and "API keys".

## 1. Grok (custom connector)

1. Dashboard: create a connection "Grok assistant", 90 days. Copy its URL.
2. In the Grok app, add a custom connector with only that URL.
3. Expected: the browser opens Komogentic's consent page: "**Grok** wants to use your connection **Grok assistant**: your Komodo stacks with your rights." Allow.
4. Expected: Grok shows the connector as connected; the dashboard shows the connection as *Connected* with Grok as its app, and Komodo lists an API key `komogentic/Grok assistant` for the user, expiring in 90 days.
5. Ask: "Which of my stacks are green?" → Grok calls `list_stacks`; the answer lists `app` and `other`, no stack the user can't see.
6. Ask: "Show the last 50 log lines of app" → `get_stack_logs`.
7. Ask: "Deploy app" → Grok asks to confirm (the tool is marked as changing); confirm. Expected: "deploy succeeded in … s; app is green" (or the failure with its log). Komodo shows the user as the operator; Komogentic's log has an audit line with the connection, Grok, `deploy_stack`, `app` and the outcome.
8. Ask: "Deploy other" → "your Komodo user lacks Execute on stack other".
9. Revoke the connection in the dashboard → the next tool call in Grok fails with a sign-in prompt; Komodo no longer lists `komogentic/Grok assistant`.

## 2. claude.ai (custom connector)

1. Dashboard: create a connection "Claude", 30 days.
2. claude.ai → Settings → Connectors → Add custom connector, with only the URL.
3. Expected: consent page as above; Allow; claude.ai shows *Connected*.
4. Repeat steps 5–8 of Grok. Claude asks before `deploy_stack` and `restart_stack`.
5. Wait more than an hour (an access token's lifetime) and ask again: the call works without a new consent (refresh).
6. In Komodo, delete the key `komogentic/Claude`. Ask again → the tool answers that Komodo rejected the key; the dashboard shows *Needs reconnect* with "Komodo no longer accepts this connection's key". In claude.ai, reconnect the connector → consent again → Allow → works; Komodo lists a new `komogentic/Claude` key.

## 3. Claude Code with an API key

1. Dashboard: create an API key "Claude Code", never expiring. Copy it (shown once).
2. `claude mcp add --transport http komogentic https://komogentic.example.org/mcp --header "Authorization: Bearer kgt_…"`
3. `claude mcp list` → komogentic connected. In a session: "list my stacks", "status of app", "restart app with wait_seconds 300".
4. Expected: as above; the dashboard's key shows a *last used* time.
5. Revoke the key → the next call answers 401; Komodo no longer lists `komogentic/Claude Code`.

## 4. Hermes (or another local agent) with an API key

1. Dashboard: create an API key "Hermes".
2. Configure Hermes's MCP server as `https://komogentic.example.org/mcp` with the header `Authorization: Bearer kgt_…`.
3. Ask it to find why `app` is red: it should call `list_stacks`, `get_stack_status app`, `get_stack_logs app` with `search`, and `list_stack_updates app`.
4. In Komodo, delete `komogentic/Hermes` → the next call answers that Komodo rejected the key; the dashboard shows the key as "No longer accepted by Komodo".

## What to note

For every step that doesn't behave as expected: the client and its version, the time (UTC), what the client showed, and Komogentic's log lines around that time (`docker compose logs komogentic`; they hold no secrets).
