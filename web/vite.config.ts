// SPDX-License-Identifier: AGPL-3.0-or-later
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

const server = "http://localhost:8080";

export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": server, "/mcp": server, "/oauth": server, "/.well-known": server } },
  test: { environment: "jsdom", globals: true, setupFiles: ["./src/test-setup.ts"] },
});
