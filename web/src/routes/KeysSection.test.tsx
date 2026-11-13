// SPDX-License-Identifier: AGPL-3.0-or-later
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ApiKeyView } from "../api";
import { fakeApi, renderWith } from "../test/server";
import KeysSection from "./KeysSection";

const hermes: ApiKeyView = {
  id: "0123456789abcdef0123456789abcdef",
  name: "Hermes",
  createdAt: "2026-11-12T10:00:00Z",
  lastUsedAt: null,
  expiresAt: null,
  state: "active",
  reason: null,
};
const secret = "kgt_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg";

test("shows a new key once", async () => {
  let list: ApiKeyView[] = [];
  fakeApi({
    "GET /api/keys": () => ({ status: 200, json: list }),
    "POST /api/keys": () => {
      list = [hermes];
      return { status: 201, json: { key: hermes, secret } };
    },
  });
  renderWith(<KeysSection />);

  await userEvent.type(screen.getByLabelText("Key name"), "Hermes");
  await userEvent.selectOptions(screen.getByLabelText("Key expiry"), "never");
  await userEvent.click(screen.getByRole("button", { name: "Create API key" }));

  const reveal = await screen.findByRole("region", { name: "New API key" });
  expect(within(reveal).getByLabelText("API key")).toHaveValue(secret);
  // Listed by name, never with its secret.
  const list_ = await screen.findByRole("heading", { name: "Hermes", level: 3 });
  expect(list_.closest("li")).not.toHaveTextContent(secret);
});

test("revokes", async () => {
  const calls = fakeApi({
    "GET /api/keys": () => ({ status: 200, json: [hermes] }),
    "DELETE /api/keys/0123456789abcdef0123456789abcdef": () => ({ status: 204 }),
  });
  vi.spyOn(window, "confirm").mockReturnValue(true);
  renderWith(<KeysSection />);

  await userEvent.click(await screen.findByRole("button", { name: "Revoke Hermes" }));

  expect(calls.filter((c) => c.method === "DELETE")).toHaveLength(1);
});

test("explains a key Komodo no longer accepts", async () => {
  fakeApi({ "GET /api/keys": () => ({ status: 200, json: [{ ...hermes, state: "dead", reason: "komodo_key_rejected" }] }) });
  renderWith(<KeysSection />);

  expect(await screen.findByText("No longer accepted by Komodo")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Revoke Hermes" })).not.toBeInTheDocument();
});
