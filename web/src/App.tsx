// SPDX-License-Identifier: AGPL-3.0-or-later
import { Route, Routes } from "react-router-dom";
import { errorText, useSession } from "./api";
import Consent from "./routes/Consent";
import Home from "./routes/Home";
import SignIn from "./routes/SignIn";

export default function App() {
  const session = useSession();
  if (session.isPending) return <main className="narrow">Loading…</main>;
  if (session.isError) return <main className="narrow"><p role="alert" className="error">{errorText(session.error)}</p></main>;

  return (
    <Routes>
      <Route path="/consent" element={<Consent signedIn={session.data !== null} />} />
      <Route path="*" element={session.data ? <Home session={session.data} /> : <SignIn />} />
    </Routes>
  );
}
