// SPDX-License-Identifier: AGPL-3.0-or-later
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import SignIn from "./SignIn";

function renderSignIn() {
  return render(
    <QueryClientProvider client={new QueryClient()}>
      <MemoryRouter>
        <SignIn />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

test("renders the sign-in form", () => {
  renderSignIn();
  expect(screen.getByLabelText("Komodo username")).toBeInTheDocument();
  expect(screen.getByLabelText("Password")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
});
