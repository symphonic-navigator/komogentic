# Komogentic — notes for Claude

Komogentic is an MCP gateway to Komodo: agents read logs, check status, and deploy or restart stacks, each with the Komodo account and rights of the person it works for. A C# (.NET 10) server in `src/`, a React/Vite web app in `web/`, MongoDB for storage. `README.md` describes the product and its configuration; `docs/superpowers/specs/2026-11-12-komogentic-design.md` the design.

## Language and style

- Code, comments, docs, commit messages, PR descriptions: **British English** (colour, behaviour, initialise, licence as the noun).
- Match the surrounding code: its comment density, naming and idiom. Comments only where the reasoning isn't obvious. Source files start with `// SPDX-License-Identifier: AGPL-3.0-or-later` (or their language's comment form).
- Modern C#: records, pattern matching, minimal APIs. No ORM: the MongoDB driver directly.
- The repository names no organisation, customer, employer, person or host: not in code, tests, examples, configuration or the README. Use neutral names such as "Anna" and `komogentic.example.org`. Deployment-specific settings go into `.env` or a `compose.override.yaml`, never into the repository. Allowed: the image name `ghcr.io/symphonic-navigator/komogentic` and the repository URL; upstream projects and clients (Komodo and moghtech, MP-Tool, Kumbu², Grok, claude.ai, ChatGPT, Hermes, Anthropic's egress range).
- Every environment variable appears in `.env.example` with a realistic placeholder and in the README's configuration table with what it does, its format and an example.

## Security rules

- Never a static, shared or environment-configured Komodo key, not even in development or for a demo. Every Komodo call outside the sign-in uses a key created for the calling user.
- The Komodo calls are a closed list (`src/Komogentic.Server/Komodo/KomodoCalls.cs`); `ClosedListTests` fails if any other Komodo request type appears in the source. Adding one is a spec change.
- No secret (password, JWT, Komodo secret, token, cookie) in logs, URLs, browser storage or test failure messages.

## Build and test

```sh
# MongoDB for the tests: set KOMOGENTIC_TEST_MONGO, or the tests start a Testcontainer (mongo:8).
export KOMOGENTIC_TEST_MONGO="mongodb://localhost:27017/?replicaSet=rs0&directConnection=true"
dotnet restore --locked-mode && dotnet build --configuration Release --no-restore
dotnet test --solution Komogentic.slnx --configuration Release --no-build
pnpm -C web install --frozen-lockfile      # first, or after a pull: stale node_modules make tests and build fail
pnpm -C web test --run
pnpm -C web build
```

A MongoDB for the tests, as a single-node replica set:

```sh
docker run -d --name komogentic-test-mongo -p 27017:27017 mongo:8 --replSet rs0 --bind_ip_all
docker exec komogentic-test-mongo mongosh --quiet --eval 'rs.initiate({_id: "rs0", members: [{_id: 0, host: "127.0.0.1:27017"}]})'
```

xUnit v3 for the server, Vitest for the web app. No tests for trivial getters. Never work around an empty suite with `--ignore-exit-code` or `passWithNoTests`.

## Git and pull requests

- A branch per change, a pull request, squash merge. Commit messages imperative and free-form ("Add the deploy tool"), no Conventional Commits prefix.
- CI (`.github/workflows/ci.yml`) and the image build (`docker.yml`) run on every pull request. A push to `master` publishes `:master` and `:sha-…` images; only a version tag publishes `:latest`, which deployments (Komodo itself) follow.
- Specs go to `docs/superpowers/specs/YYYY-MM-DD-<topic>-design.md`, plans to `docs/superpowers/plans/`.

## Releasing

Only when the maintainer asks for a release.

1. Set the version in `version.txt`, `src/Komogentic.Server/Komogentic.Server.csproj` (`<Version>`) and `web/package.json`; move the `CHANGELOG.md` entry from "unreleased" to the date.
2. Pull request "Release vX.Y.Z", squash merge once CI is green.
3. Annotated tag on the merge commit: `git tag -a vX.Y.Z -m "Komogentic X.Y.Z"`, then `git push origin vX.Y.Z`. The tag's image build is the release; there are no GitHub release objects.

A pre-release, for trying a build on a server pinned to it: an annotated tag `vX.Y.Z-pre.N` (`-m "Komogentic X.Y.Z-pre.N"`) on a `master` commit, without a release pull request; the version comes from the tag, and `:latest` stays where it is.

## Dependabot

Pull requests for NuGet packages of `src/Komogentic.Server` fail CI with `NU1004`: Dependabot updates the server's `packages.lock.json` but not the test project's. On the branch, merge `master`, run `dotnet restore Komogentic.slnx --force-evaluate`, commit the lock files, run the full test suite.

Images are signed with cosign 3 (Sigstore bundle format); the README's `cosign verify` needs cosign 3 or newer.
