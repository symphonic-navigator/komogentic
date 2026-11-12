// SPDX-License-Identifier: AGPL-3.0-or-later
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { ApiError, dateText, errorText, request, type ConsentView } from "../api";
import SignIn from "./SignIn";

/** The errors /oauth/authorize sends here before it trusts the app's redirect address. */
const authorizeErrors: Record<string, string> = {
  unknown_client: "The app that sent you here could not be identified. Start connecting again in the app.",
  invalid_redirect_uri: "The app asked to return to an address that isn't its own. Start connecting again in the app.",
  temporarily_unavailable: "Too many apps are being identified right now. Wait a minute, then start connecting again in the app.",
};

const problems: Record<NonNullable<ConsentView["problem"]>, string> = {
  not_a_connection: "The app was given an address that isn't a connection's URL. Create a connection in Komogentic and add its URL in the app.",
  revoked: "This connection was revoked. Create a new connection and add its URL in the app.",
  expired: "This connection has expired. Create a new connection and add its URL in the app.",
};

function Decision({ id }: { id: string }) {
  const queryClient = useQueryClient();
  const consent = useQuery({ queryKey: ["consent", id], queryFn: () => request<ConsentView>("GET", `/api/oauth/requests/${encodeURIComponent(id)}`) });
  const decide = useMutation({
    mutationFn: (allow: boolean) => request<{ redirect: string }>("POST", `/api/oauth/requests/${encodeURIComponent(id)}/decision`, { allow }),
    onSuccess: ({ redirect }) => window.location.assign(redirect),
  });
  const signOut = useMutation({
    mutationFn: () => request<void>("DELETE", "/api/session"),
    onSettled: () => {
      queryClient.removeQueries({ predicate: (q) => q.queryKey[0] !== "session" });
      queryClient.setQueryData(["session"], null);
    },
  });

  if (consent.isPending) return <p>Loading…</p>;
  if (consent.isError) {
    const otherAccount = consent.error instanceof ApiError && consent.error.type === "other-account";
    return (
      <>
        <p role="alert" className="error">{errorText(consent.error)}</p>
        {otherAccount && (
          <button type="button" onClick={() => signOut.mutate()}>
            Sign out and sign in as the connection's owner
          </button>
        )}
      </>
    );
  }

  const view = consent.data;
  return (
    <>
      {view.connection ? (
        <p className="ask">
          <strong>{view.client.name}</strong> wants to use your connection <strong>{view.connection.name}</strong>: your Komodo stacks with your rights
          {view.readOnly ? ", read only (no deploy or restart)" : ""}.
        </p>
      ) : (
        <p className="ask">
          <strong>{view.client.name}</strong> wants to connect.
        </p>
      )}
      <p className="meta">
        You return to {view.redirectHost} afterwards.
        {!view.client.verified && ` The app named itself “${view.client.name}”; Komogentic could not check that name.`}
        {view.connection && ` The connection expires ${dateText(view.connection.expiresAt)}.`}
        {view.connection?.currentClient && ` It is now used by ${view.connection.currentClient.name}; allowing replaces that.`}
      </p>
      {view.problem && <p role="alert" className="error">{problems[view.problem]}</p>}
      {decide.isError && <p role="alert" className="error">{errorText(decide.error)}</p>}
      <div className="buttons">
        {!view.problem && (
          <button type="button" className="primary" disabled={decide.isPending} onClick={() => decide.mutate(true)}>
            Allow
          </button>
        )}
        <button type="button" disabled={decide.isPending} onClick={() => decide.mutate(false)}>
          Deny
        </button>
      </div>
    </>
  );
}

/** Where /oauth/authorize sends the browser: `?request=` to decide, `?error=` to explain. Signs in first if needed. */
export default function Consent({ signedIn }: { signedIn: boolean }) {
  const [params] = useSearchParams();
  const error = params.get("error");
  const id = params.get("request");

  if (error || !id) {
    return (
      <main className="narrow">
        <h1>Komogentic</h1>
        <p role="alert" className="error">{(error && authorizeErrors[error]) ?? "This page is opened by an app that connects to Komogentic."}</p>
      </main>
    );
  }

  if (!signedIn) return <SignIn intro="An app wants to connect. Sign in with your Komodo username and password first." />;

  return (
    <main className="narrow">
      <h1>Allow access?</h1>
      <Decision id={id} />
    </main>
  );
}
