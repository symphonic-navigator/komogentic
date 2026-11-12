// SPDX-License-Identifier: AGPL-3.0-or-later
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";

type Handler = (body: unknown) => { status: number; json?: unknown };

/** A fake API: `"METHOD /path"` → handler. Records every call; an unknown one fails the test. */
export function fakeApi(routes: Record<string, Handler>) {
  const calls: { method: string; path: string; body: unknown }[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    const path = typeof input === "string" ? input : input.toString();
    const body = init?.body ? (JSON.parse(init.body as string) as unknown) : undefined;
    calls.push({ method, path, body });
    const handler = routes[`${method} ${path}`];
    if (!handler) throw new Error(`Unexpected request ${method} ${path}`);
    const { status, json } = handler(body);
    return new Response(status === 204 ? null : JSON.stringify(json ?? {}), { status, headers: { "Content-Type": "application/json" } });
  });
  vi.stubGlobal("fetch", fetchMock);
  return calls;
}

export function renderWith(ui: ReactNode, path = "/") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});
