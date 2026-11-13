// SPDX-License-Identifier: AGPL-3.0-or-later
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ConnectionView } from "../api";
import { fakeApi, renderWith } from "../test/server";
import ConnectionsSection from "./ConnectionsSection";

const grok: ConnectionView = {
  id: "q8m2x7abcdefghij",
  name: "Grok assistant",
  url: "https://komogentic.example.org/mcp/c/q8m2x7abcdefghij",
  createdAt: "2026-11-12T10:00:00Z",
  lastUsedAt: null,
  expiresAt: "2027-02-10T10:00:00Z",
  state: "waiting",
  reason: null,
  client: null,
};

test("creates a connection and shows its URL with a copy button", async () => {
  let list: ConnectionView[] = [];
  const calls = fakeApi({
    "GET /api/connections": () => ({ status: 200, json: list }),
    "POST /api/connections": () => {
      list = [grok];
      return { status: 201, json: grok };
    },
  });
  renderWith(<ConnectionsSection />);

  await userEvent.type(screen.getByLabelText("Connection name"), "Grok assistant");
  await userEvent.click(screen.getByRole("button", { name: "Create connection" }));

  const reveal = await screen.findByRole("region", { name: "New connection" });
  expect(within(reveal).getByLabelText("MCP URL")).toHaveValue(grok.url);
  expect(within(reveal).getByRole("button", { name: "Copy mcp url" })).toBeInTheDocument();
  expect(calls.find((c) => c.method === "POST")?.body).toEqual({ name: "Grok assistant", expiresInDays: 90 });
});

test("shows needs reconnect with the reason", async () => {
  fakeApi({
    "GET /api/connections": () => ({
      status: 200,
      json: [{ ...grok, state: "needs_reconnect", reason: "komodo_key_rejected", client: { name: "Grok", host: "grok.com", verified: true } }],
    }),
  });
  renderWith(<ConnectionsSection />);

  expect(await screen.findByText("Needs reconnect")).toBeInTheDocument();
  expect(screen.getByText(/Komodo no longer accepts this connection's key/)).toBeInTheDocument();
});

test("revokes after confirmation", async () => {
  const calls = fakeApi({
    "GET /api/connections": () => ({ status: 200, json: [grok] }),
    "DELETE /api/connections/q8m2x7abcdefghij": () => ({ status: 204 }),
  });
  const confirm = vi.spyOn(window, "confirm").mockReturnValueOnce(false).mockReturnValueOnce(true);
  renderWith(<ConnectionsSection />);

  const button = await screen.findByRole("button", { name: "Revoke Grok assistant" });
  await userEvent.click(button);
  expect(calls.some((c) => c.method === "DELETE")).toBe(false);
  await userEvent.click(button);

  expect(confirm).toHaveBeenCalledTimes(2);
  expect(calls.filter((c) => c.method === "DELETE")).toHaveLength(1);
});
