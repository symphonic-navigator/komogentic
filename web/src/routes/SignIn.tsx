// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState, type FormEvent } from "react";

/** Sign in with the Komodo account: Komogentic has no users of its own. */
export default function SignIn() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  function submit(e: FormEvent) {
    e.preventDefault();
  }

  return (
    <main className="narrow">
      <h1>Komogentic</h1>
      <p>Sign in with your Komodo username and password.</p>
      <form onSubmit={submit}>
        <label>
          Komodo username
          <input autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
        </label>
        <label>
          Password
          <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </label>
        <button type="submit">Sign in</button>
      </form>
    </main>
  );
}
