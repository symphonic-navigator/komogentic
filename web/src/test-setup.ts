// SPDX-License-Identifier: AGPL-3.0-or-later
import "@testing-library/jest-dom/vitest";

// React Router builds a Request with an AbortSignal for every navigation. Under jsdom that signal is jsdom's,
// which Node's own Request refuses; tests never abort a request, so the signal is dropped.
const NodeRequest = globalThis.Request;
globalThis.Request = class extends NodeRequest {
  constructor(input: RequestInfo | URL, init?: RequestInit) {
    super(input, init?.signal ? { ...init, signal: undefined } : init);
  }
};
