// SPDX-License-Identifier: AGPL-3.0-or-later
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "../App";
import { fakeApi, renderWith } from "../test/server";
import SignIn from "./SignIn";

const empty = { "GET /api/connections": () => ({ status: 200, json: [] }), "GET /api/keys": () => ({ status: 200, json: [] }) };

async function fillIn() {
  await userEvent.type(await screen.findByLabelText("Komodo username"), "anna");
  await userEvent.type(screen.getByLabelText("Password"), "correct horse");
  await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
}

test("renders the sign-in form", () => {
  renderWith(<SignIn />);
  expect(screen.getByLabelText("Komodo username")).toBeInTheDocument();
  expect(screen.getByLabelText("Password")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
});

test("signs in and shows the dashboard", async () => {
  const calls = fakeApi({
    "GET /api/session": () => ({ status: 401, json: { error: "Sign in with your Komodo username and password." } }),
    "POST /api/session": () => ({ status: 200, json: { username: "anna", expiresAt: "2026-11-13T09:00:00Z" } }),
    ...empty,
  });
  renderWith(<App />);
  await fillIn();

  expect(await screen.findByText("anna")).toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "Connections" })).toBeInTheDocument();
  expect(calls.find((c) => c.method === "POST")?.body).toEqual({ username: "anna", password: "correct horse" });
});

test("shows Komodo's refusal", async () => {
  fakeApi({ "POST /api/session": () => ({ status: 401, json: { error: "Komodo refused this username and password." } }) });
  renderWith(<SignIn />);
  await fillIn();

  expect(await screen.findByRole("alert")).toHaveTextContent("Komodo refused this username and password.");
  expect(screen.getByLabelText("Password")).toHaveValue("");
});

test("explains two-factor is unsupported", async () => {
  fakeApi({
    "POST /api/session": () => ({
      status: 400,
      json: { error: "Two-factor sign-in is not supported: sign in with a Komodo user without a second factor." },
    }),
  });
  renderWith(<SignIn />);
  await fillIn();

  expect(await screen.findByRole("alert")).toHaveTextContent("Two-factor sign-in is not supported");
});
