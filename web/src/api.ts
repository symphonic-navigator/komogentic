// SPDX-License-Identifier: AGPL-3.0-or-later
import { useQuery } from "@tanstack/react-query";

/** A refusal of the server's API: its status and its one sentence for a person; `type` for those the app answers itself. */
export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly type?: string,
  ) {
    super(message);
  }
}

/** A same-origin call of the API; the session cookie goes with it, nothing is kept in browser storage. */
export async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const response = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: body === undefined ? { Accept: "application/json" } : { Accept: "application/json", "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  const json = text ? (JSON.parse(text) as unknown) : undefined;
  if (!response.ok) {
    const error = json as { error?: string; type?: string } | undefined;
    throw new ApiError(response.status, error?.error ?? `The server answered ${response.status}.`, error?.type);
  }
  return json as T;
}

export interface SessionView {
  username: string;
  expiresAt: string;
}

export interface ClientView {
  name: string;
  host: string;
  verified: boolean;
}

export interface ConnectionView {
  id: string;
  name: string;
  url: string;
  createdAt: string;
  lastUsedAt: string | null;
  expiresAt: string | null;
  state: "waiting" | "connected" | "needs_reconnect" | "revoked" | "expired";
  reason: string | null;
  client: ClientView | null;
}

export interface ApiKeyView {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt: string | null;
  expiresAt: string | null;
  state: "active" | "revoked" | "expired" | "dead";
  reason: string | null;
}

export interface CreatedKey {
  key: ApiKeyView;
  secret: string;
}

export interface ConsentView {
  requestId: string;
  client: ClientView;
  redirectHost: string;
  connection: { name: string; expiresAt: string | null; currentClient: ClientView | null } | null;
  readOnly: boolean;
  renewal: boolean;
  problem: "not_a_connection" | "revoked" | "expired" | null;
}

/** The signed-in user, or null when there is no session (a 401). */
export function useSession() {
  return useQuery({
    queryKey: ["session"],
    queryFn: async () => {
      try {
        return await request<SessionView>("GET", "/api/session");
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) return null;
        throw e;
      }
    },
  });
}

export const useConnections = () => useQuery({ queryKey: ["connections"], queryFn: () => request<ConnectionView[]>("GET", "/api/connections") });

export const useKeys = () => useQuery({ queryKey: ["keys"], queryFn: () => request<ApiKeyView[]>("GET", "/api/keys") });

export function errorText(e: unknown): string {
  return e instanceof Error ? e.message : "Something went wrong.";
}

export function dateText(iso: string | null, none = "never"): string {
  return iso ? new Date(iso).toLocaleString() : none;
}
