// SPDX-License-Identifier: AGPL-3.0-or-later
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { errorText, request, type SessionView } from "../api";

/** Sign in with the Komodo account: Komogentic has no users of its own and keeps no password. */
export default function SignIn({ intro }: { intro?: string }) {
  const queryClient = useQueryClient();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const signIn = useMutation({
    mutationFn: () => request<SessionView>("POST", "/api/session", { username, password }),
    onSuccess: (session) => {
      // Nothing cached from an earlier session, maybe another user's, outlives this sign-in. Not clear(): the
      // session's query must stay, with its observers, to show the new session.
      queryClient.removeQueries({ predicate: (q) => q.queryKey[0] !== "session" });
      queryClient.setQueryData(["session"], session);
    },
    onSettled: () => setPassword(""),
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    signIn.mutate();
  }

  return (
    <main className="narrow">
      <h1>Komogentic</h1>
      <p>{intro ?? "Sign in with your Komodo username and password."}</p>
      <form onSubmit={submit}>
        <label>
          Komodo username
          <input autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
        </label>
        <label>
          Password
          <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </label>
        {signIn.isError && <p role="alert" className="error">{errorText(signIn.error)}</p>}
        <button type="submit" disabled={signIn.isPending}>
          Sign in
        </button>
      </form>
    </main>
  );
}
