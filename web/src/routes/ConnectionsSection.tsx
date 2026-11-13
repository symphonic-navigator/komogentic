// SPDX-License-Identifier: AGPL-3.0-or-later
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { dateText, errorText, request, useConnections, type ConnectionView } from "../api";
import { CopyField } from "./Reveal";

const reasons: Record<string, string> = {
  komodo_key_rejected: "Komodo no longer accepts this connection's key (it was deleted in Komodo). Add the URL in the app again to reconnect.",
  client_revoked: "The app signed out of this connection. Add the URL in the app again to reconnect.",
  refresh_reused: "An old token of this connection was used again, so its tokens were revoked to be safe. Add the URL in the app again to reconnect.",
  code_reused: "An authorisation code was used twice, so this connection's tokens were revoked to be safe. Add the URL in the app again to reconnect.",
  code_unused: "The app never finished connecting. Add the URL in the app again.",
  reconnected: "The app connected again; the earlier tokens were replaced.",
};

const states: Record<ConnectionView["state"], string> = {
  waiting: "Waiting for the app",
  connected: "Connected",
  needs_reconnect: "Needs reconnect",
  revoked: "Revoked",
  expired: "Expired",
};

export function reasonText(reason: string | null): string | null {
  return reason ? (reasons[reason] ?? reason) : null;
}

/** What a new connection's owner does next, per app. */
function Instructions({ connection }: { connection: ConnectionView }) {
  return (
    <section className="reveal" aria-label="New connection">
      <h3>Connection “{connection.name}” is ready</h3>
      <CopyField label="MCP URL" value={connection.url} />
      <ul>
        <li>
          <strong>Grok, claude.ai:</strong> add a custom connector with this URL. The app sends you here to allow it.
        </li>
        <li>
          <strong>ChatGPT (web):</strong> add a connector with this URL and OAuth; it registers itself.
        </li>
        <li>
          <strong>Apps without OAuth</strong> (ChatGPT desktop, Hermes, Claude Code): use an API key below instead.
        </li>
      </ul>
    </section>
  );
}

export default function ConnectionsSection() {
  const queryClient = useQueryClient();
  const connections = useConnections();
  const [name, setName] = useState("");
  const [expiry, setExpiry] = useState("90");
  const [created, setCreated] = useState<ConnectionView | null>(null);

  const create = useMutation({
    mutationFn: () => request<ConnectionView>("POST", "/api/connections", { name, expiresInDays: expiry === "never" ? null : Number(expiry) }),
    onSuccess: (connection) => {
      setCreated(connection);
      setName("");
      void queryClient.invalidateQueries({ queryKey: ["connections"] });
    },
  });
  const revoke = useMutation({
    mutationFn: (id: string) => request<void>("DELETE", `/api/connections/${encodeURIComponent(id)}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["connections"] }),
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    create.mutate();
  }

  return (
    <section aria-labelledby="connections">
      <h2 id="connections">Connections</h2>
      <p>For apps that connect with OAuth: Grok, claude.ai, ChatGPT. Each one acts as you in Komodo, with your rights.</p>
      <form onSubmit={submit} className="inline">
        <label>
          Connection name
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={60} required placeholder="Grok assistant" />
        </label>
        <label>
          Connection expiry
          <select value={expiry} onChange={(e) => setExpiry(e.target.value)}>
            <option value="30">30 days</option>
            <option value="90">90 days</option>
            <option value="365">365 days</option>
            <option value="never">Never</option>
          </select>
        </label>
        <button type="submit" disabled={create.isPending}>
          Create connection
        </button>
      </form>
      {create.isError && <p role="alert" className="error">{errorText(create.error)}</p>}
      {created && <Instructions connection={created} />}
      {connections.isError && <p role="alert" className="error">{errorText(connections.error)}</p>}
      <ul className="items">
        {connections.data?.map((c) => (
          <li key={c.id}>
            <h3>{c.name}</h3>
            <p>
              <span className={`state ${c.state}`}>{states[c.state]}</span>
              {c.client && <> · {c.client.name} ({c.client.host})</>}
            </p>
            {reasonText(c.reason) && c.state === "needs_reconnect" && <p className="note">{reasonText(c.reason)}</p>}
            {(c.state === "waiting" || c.state === "connected" || c.state === "needs_reconnect") && <CopyField label="MCP URL" value={c.url} />}
            <p className="meta">
              Created {dateText(c.createdAt)} · last used {dateText(c.lastUsedAt)} · expires {dateText(c.expiresAt)}
            </p>
            {c.state !== "revoked" && c.state !== "expired" && (
              <button
                type="button"
                onClick={() => {
                  if (window.confirm(`Revoke “${c.name}”? The app loses access at once, and its Komodo key is deleted.`)) revoke.mutate(c.id);
                }}
              >
                Revoke {c.name}
              </button>
            )}
          </li>
        ))}
      </ul>
      {revoke.isError && <p role="alert" className="error">{errorText(revoke.error)}</p>}
    </section>
  );
}
