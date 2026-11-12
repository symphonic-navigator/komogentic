// SPDX-License-Identifier: AGPL-3.0-or-later
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "../App";
import type { ConsentView } from "../api";
import { fakeApi, renderWith } from "../test/server";

const view: ConsentView = {
  requestId: "r1",
  client: { name: "Grok", host: "grok.com", verified: true },
  redirectHost: "grok.com",
  connection: { name: "Grok assistant", expiresAt: null, currentClient: null },
  readOnly: false,
  renewal: false,
  problem: null,
};
const session = { "GET /api/session": () => ({ status: 200, json: { username: "anna", expiresAt: "2026-11-13T09:00:00Z" } }) };

beforeEach(() => {
  vi.stubGlobal("location", { ...window.location, assign: vi.fn() });
});

test("shows the client and connection and allows", async () => {
  const calls = fakeApi({
    ...session,
    "GET /api/oauth/requests/r1": () => ({ status: 200, json: view }),
    "POST /api/oauth/requests/r1/decision": () => ({ status: 200, json: { redirect: "https://grok.com/callback?code=x&iss=y" } }),
  });
  renderWith(<App />, "/consent?request=r1");

  expect(await screen.findByText(/wants to use your connection/)).toHaveTextContent(
    "Grok wants to use your connection Grok assistant: your Komodo stacks with your rights.",
  );
  await userEvent.click(screen.getByRole("button", { name: "Allow" }));

  expect(calls.find((c) => c.method === "POST")?.body).toEqual({ allow: true });
  await vi.waitFor(() => expect(window.location.assign).toHaveBeenCalledWith("https://grok.com/callback?code=x&iss=y"));
});

test("denies", async () => {
  const calls = fakeApi({
    ...session,
    "GET /api/oauth/requests/r1": () => ({ status: 200, json: view }),
    "POST /api/oauth/requests/r1/decision": () => ({ status: 200, json: { redirect: "https://grok.com/callback?error=access_denied" } }),
  });
  renderWith(<App />, "/consent?request=r1");

  await userEvent.click(await screen.findByRole("button", { name: "Deny" }));

  expect(calls.find((c) => c.method === "POST")?.body).toEqual({ allow: false });
});

test("shows only Deny for a revoked connection", async () => {
  fakeApi({ ...session, "GET /api/oauth/requests/r1": () => ({ status: 200, json: { ...view, problem: "revoked" } }) });
  renderWith(<App />, "/consent?request=r1");

  expect(await screen.findByRole("button", { name: "Deny" })).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Allow" })).not.toBeInTheDocument();
  expect(screen.getByRole("alert")).toHaveTextContent("This connection was revoked.");
});

test("says read only when the app asked to read only", async () => {
  fakeApi({ ...session, "GET /api/oauth/requests/r1": () => ({ status: 200, json: { ...view, readOnly: true } }) });
  renderWith(<App />, "/consent?request=r1");

  expect(await screen.findByText(/wants to use your connection/)).toHaveTextContent("read only (no deploy or restart)");
});

test("asks to sign in first and comes back to the request", async () => {
  let signedIn = false;
  fakeApi({
    "GET /api/session": () => (signedIn ? session["GET /api/session"]() : { status: 401, json: { error: "Sign in." } }),
    "POST /api/session": () => {
      signedIn = true;
      return { status: 200, json: { username: "anna", expiresAt: "2026-11-13T09:00:00Z" } };
    },
    "GET /api/oauth/requests/r1": () => ({ status: 200, json: view }),
  });
  renderWith(<App />, "/consent?request=r1");

  expect(await screen.findByText(/An app wants to connect/)).toBeInTheDocument();
  await userEvent.type(screen.getByLabelText("Komodo username"), "anna");
  await userEvent.type(screen.getByLabelText("Password"), "correct horse");
  await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

  expect(await screen.findByRole("button", { name: "Allow" })).toBeInTheDocument();
});

test("offers to sign out for another account's request", async () => {
  fakeApi({
    ...session,
    "GET /api/oauth/requests/r1": () => ({ status: 404, json: { error: "This request is for another Komodo user.", type: "other-account" } }),
  });
  renderWith(<App />, "/consent?request=r1");

  expect(await screen.findByRole("button", { name: /Sign out and sign in/ })).toBeInTheDocument();
});

test("explains an unknown client error", async () => {
  fakeApi(session);
  renderWith(<App />, "/consent?error=unknown_client");

  expect(await screen.findByRole("alert")).toHaveTextContent("could not be identified");
});
