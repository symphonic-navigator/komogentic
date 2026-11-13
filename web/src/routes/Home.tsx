// SPDX-License-Identifier: AGPL-3.0-or-later
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { request, type SessionView } from "../api";
import ConnectionsSection from "./ConnectionsSection";
import KeysSection from "./KeysSection";

export default function Home({ session }: { session: SessionView }) {
  const queryClient = useQueryClient();
  const signOut = useMutation({
    mutationFn: () => request<void>("DELETE", "/api/session"),
    onSettled: () => {
      queryClient.removeQueries({ predicate: (q) => q.queryKey[0] !== "session" });
      queryClient.setQueryData(["session"], null);
    },
  });

  return (
    <main>
      <header className="bar">
        <h1>Komogentic</h1>
        <span>
          Signed in as <strong>{session.username}</strong>{" "}
          <button type="button" onClick={() => signOut.mutate()}>
            Sign out
          </button>
        </span>
      </header>
      <p>Agents reach your Komodo stacks through these, with your Komodo rights: they can list stacks, read logs and updates, deploy and restart.</p>
      <ConnectionsSection />
      <KeysSection />
    </main>
  );
}
