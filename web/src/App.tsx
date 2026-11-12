// SPDX-License-Identifier: AGPL-3.0-or-later
import { Route, Routes } from "react-router-dom";
import SignIn from "./routes/SignIn";

export default function App() {
  return (
    <Routes>
      <Route path="*" element={<SignIn />} />
    </Routes>
  );
}
