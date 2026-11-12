// SPDX-License-Identifier: AGPL-3.0-or-later
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { dateText, errorText, request, useKeys, type ApiKeyView, type CreatedKey } from "../api";
import { CopyField } from "./Reveal";

const states: Record<ApiKeyView["state"], string> = { active: "Active", revoked: "Revoked", expired: "Expired", dead: "No longer accepted by Komodo" };

/** The key just created, shown once with what to do with it; it is gone when the page is left. */
function NewKey({ created }: { created: CreatedKey }) {
  const mcp = `${window.location.origin}/mcp`;
  return (
    <section className="reveal" aria-label="New API key">
      <h3>API key “{created.key.name}”</h3>
      <p>Copy it now: it is shown only this once.</p>
      <CopyField label="API key" value={created.secret} />
      <CopyField label="MCP endpoint" value={mcp} />
      <ul>
        <li>
          <strong>Claude Code:</strong> <code>{`claude mcp add --transport http komogentic ${mcp} --header "Authorization: Bearer ${created.secret}"`}</code>
        </li>
        <li>
          <strong>Hermes and other local agents, ChatGPT desktop:</strong> the MCP endpoint above with the header <code>Authorization: Bearer …</code> and this key.
        </li>
      </ul>
    </section>
  );
}

export default function KeysSection() {
  const queryClient = useQueryClient();
  const keys = useKeys();
  const [name, setName] = useState("");
  const [expiry, setExpiry] = useState("90");
  const [created, setCreated] = useState<CreatedKey | null>(null);

  const create = useMutation({
    mutationFn: () => request<CreatedKey>("POST", "/api/keys", { name, expiresInDays: expiry === "never" ? null : Number(expiry) }),
    onSuccess: (key) => {
      setCreated(key);
      setName("");
      void queryClient.invalidateQueries({ queryKey: ["keys"] });
    },
  });
  const revoke = useMutation({
    mutationFn: (id: string) => request<void>("DELETE", `/api/keys/${encodeURIComponent(id)}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["keys"] }),
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    create.mutate();
  }

  return (
    <section aria-labelledby="keys">
      <h2 id="keys">API keys</h2>
      <p>For local agents that can't sign in with OAuth (Claude Code, Hermes). Each key acts as you in Komodo, with your rights.</p>
      <form onSubmit={submit} className="inline">
        <label>
          Key name
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={60} required placeholder="Hermes" />
        </label>
        <label>
          Key expiry
          <select value={expiry} onChange={(e) => setExpiry(e.target.value)}>
            <option value="30">30 days</option>
            <option value="90">90 days</option>
            <option value="365">365 days</option>
            <option value="never">Never</option>
          </select>
        </label>
        <button type="submit" disabled={create.isPending}>
          Create API key
        </button>
      </form>
      {create.isError && <p role="alert" className="error">{errorText(create.error)}</p>}
      {created && <NewKey created={created} />}
      {keys.isError && <p role="alert" className="error">{errorText(keys.error)}</p>}
      <ul className="items">
        {keys.data?.map((k) => (
          <li key={k.id}>
            <h3>{k.name}</h3>
            <p>
              <span className={`state ${k.state}`}>{states[k.state]}</span>
            </p>
            {k.state === "dead" && <p className="note">Komodo no longer accepts this key's Komodo key (it was deleted in Komodo). Create a new key.</p>}
            <p className="meta">
              Created {dateText(k.createdAt)} · last used {dateText(k.lastUsedAt)} · expires {dateText(k.expiresAt)}
            </p>
            {k.state === "active" && (
              <button
                type="button"
                onClick={() => {
                  if (window.confirm(`Revoke “${k.name}”? The agent loses access at once, and its Komodo key is deleted.`)) revoke.mutate(k.id);
                }}
              >
                Revoke {k.name}
              </button>
            )}
          </li>
        ))}
      </ul>
      {revoke.isError && <p role="alert" className="error">{errorText(revoke.error)}</p>}
    </section>
  );
}
