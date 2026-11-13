# SPDX-License-Identifier: AGPL-3.0-or-later
# Base images by digest, so a re-tagged image can't change what is built; the tag before the digest says which
# image it is and is what Dependabot follows (.github/dependabot.yml) when it proposes a new digest.
# node:26-slim
FROM node:26-slim@sha256:e4db4c914bf8ad241bd24804fc25d272d89bad97e68cdc8a1414862790a02c39 AS web
WORKDIR /src
COPY web/package.json web/pnpm-lock.yaml web/
# Node 25+ ships no corepack, so pnpm comes from npm, at the version web/package.json's packageManager names.
RUN npm install -g pnpm@10.32.1 && pnpm -C web install --frozen-lockfile
COPY web web
RUN pnpm -C web build

# mcr.microsoft.com/dotnet/sdk:10.0
FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:212fe4cb74627d5adf9817a4088906ae3edff1bd853bb27565d4b46731efe61e AS build
WORKDIR /src
COPY . .
# The web app is served from the server's wwwroot.
COPY --from=web /src/web/dist src/Komogentic.Server/wwwroot
# Set by the image workflow (.github/workflows/docker.yml): the SDK makes the informational version
# "$VERSION+$GIT_SHA" (BuildVersion.cs), just "$VERSION" without a commit.
ARG VERSION=0.0.0-dev
ARG GIT_SHA=""
# Locked: exactly the packages in packages.lock.json, or the build fails.
RUN dotnet restore src/Komogentic.Server --locked-mode && \
    dotnet publish src/Komogentic.Server -c Release -o /app --no-restore -p:Version="$VERSION" -p:SourceRevisionId="$GIT_SHA"

# mcr.microsoft.com/dotnet/aspnet:10.0
FROM mcr.microsoft.com/dotnet/aspnet:11.0@sha256:bc0d6653979efba491ab3d6f589d691f96c309c3c3ef81325efa6978e7b7f242
ARG VERSION=0.0.0-dev
ARG GIT_SHA=""
ARG BUILT_AT=""
WORKDIR /app
COPY --from=build /app .
COPY --from=build /src/LICENSE ./
# Version marker: set by the image workflow, `0.0.0-dev` in local builds.
RUN printf '%s\n' "$VERSION ($GIT_SHA, $BUILT_AT)" > /app/VERSION
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
USER app
ENTRYPOINT ["dotnet", "Komogentic.Server.dll"]
