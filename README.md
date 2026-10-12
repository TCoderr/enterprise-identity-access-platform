**English** · [Türkçe](README.tr.md)

# Halka ID — Enterprise Identity & Access Management Platform

**Author / owner:** TCoderr

Halka ID is a C# / .NET 10 portfolio project that demonstrates, in a single local stack, a central identity provider
(OpenID Provider), an OAuth 2.0 / OpenID Connect authorization server, single sign-on (SSO) across two demo
applications, multi-factor authentication (TOTP + recovery codes), application (client) registration, user consent,
session / grant / token revocation, and an administration UI.

> **Status and honest limits.** This is a portfolio / reference application. It has been verified end to end locally
> (`docs/final-verification.md`), but it has not been run in a production environment, has not undergone an
> independent security audit, and has not been tested with the OpenID Foundation conformance suite; it makes no claim
> of being "certified" or "production-ready". Known limitations: `docs/known-limitations.md`.

## Components

| Component | Address (local) | Role |
|---|---|---|
| **Halka ID** (`src/Halka.Iam`) | `https://id.halka.localhost:9443` | Identity provider, account and administration UI, protocol endpoints |
| **Pano** (`src/Halka.Pano`) | `https://pano.localhost:9444` | Demo client 1 (server-side session, BFF) |
| **Rapor** (`src/Halka.Rapor`) | `https://rapor.localhost:9445` | Demo client 2 (a different site; proof of SSO) |
| **Workspace API** (`src/Halka.WorkspaceApi`) | `https://workspace-api.localhost:9446` | Protected resource API (introspection) |
| **Machine demo** (`src/Halka.MachineDemo`) | — | Console client that calls the API with `client_credentials` |
| **Migrator** (`src/Halka.Migrator`) | — | Schema, restricted DB roles, seed (one-shot container) |
| PostgreSQL 17 | internal network only | Identities, sessions, grants, tokens, audit log |

Technology: ASP.NET Core 10 (Razor Pages), ASP.NET Core Identity, EF Core 10 + Npgsql, **OpenIddict 7.7.2**
(protocol, token issuance and validation), Otp.NET (TOTP), Docker Compose. No protocol or cryptography was written by hand.

## Prerequisites

- .NET SDK 10.0.401+ (`global.json`)
- Docker Engine + Compose v2
- For tests: Google Chrome (the browser tests use the installed Chrome), Node.js 24 (UI tooling only)
- Free ports: 9443–9446 (development), 9453–9456 (smoke test)

No machine-wide setting is changed: the `hosts` file, the system certificate store and global tool installation are
not needed. Browsers resolve `*.localhost` names to loopback on their own.

## Quick start

PowerShell (Windows):

```powershell
cd enterprise-identity-access-platform
./scripts/local-stack.ps1 up        # on the first run it creates .local/, builds the images and starts the stack
./scripts/local-stack.ps1 status
./scripts/local-stack.ps1 machine   # machine client demo (client_credentials → API)
./scripts/local-stack.ps1 logs -Service iam
./scripts/local-stack.ps1 down      # removes the containers; data, keys and .local/ are kept
```

Bash (Linux / macOS):

```bash
cd enterprise-identity-access-platform
./scripts/local-stack.sh up
./scripts/local-stack.sh status
./scripts/local-stack.sh machine
./scripts/local-stack.sh logs --service iam
./scripts/local-stack.sh down
```

`reset` is destructive (the database volume and `.local/` are deleted) and asks for explicit confirmation:
`./scripts/local-stack.ps1 reset -ConfirmProject halka` / `./scripts/local-stack.sh reset --confirm-project halka`.

### Certificate warning

`init` creates a local CA and server certificates for this project only (`.local/tls/`). They are not added to the
system store, which is why the browser shows a warning on first visit. Two options: accept the warning for these local
addresses, or add `.local/tls/ca.crt` as a trusted root **to your own browser profile only** (your decision; the
project does not do this for you).

### Keys and restarts

There are four separate kinds of keys and they are not used in place of one another: TLS certificates (`.local/tls/`),
token signing and encryption keys (in the database, wrapped with Data Protection), Data Protection keys
(`.local/dp-keys/`, protected with a separate wrapping certificate) and client secrets (`.local/secrets/`).

- `down` / `up` and container restarts do not change any key: the issuer address, the signing key (`kid`), sessions
  and tokens stay the same (verified by the smoke test).
- `reset`, or deleting the `.local/` directory, **recreates everything**: all sessions, tokens, MFA enrollments,
  demo passwords and client secrets become invalid; the local CA added to the browser changes as well.
- Changing the port base (`-PortBase`) changes the issuer address; it should not be done on an existing installation
  (`reset` first).

## Demo accounts and clients

Passwords and client secrets are **not** in the repository; `init` creates random ones for every installation.

| Account | Role | Password |
|---|---|---|
| `admin@halka.test` | PlatformAdmin | `.local/seed/credentials.json` |
| `secadmin@halka.test` | SecurityAdmin | `.local/seed/credentials.json` |
| `appadmin@halka.test` | ApplicationAdmin | `.local/seed/credentials.json` |
| `alice@halka.test` | User | `.local/seed/credentials.json` |

| Client | Type | Flow | Secret |
|---|---|---|---|
| `pano-web` | web (confidential) | authorization code + PKCE, refresh | `.local/secrets/client-pano` |
| `rapor-web` | web (confidential) | authorization code + PKCE, refresh | `.local/secrets/client-rapor` |
| `workspace-api` | resource | introspection only | `.local/secrets/client-workspace-api` |
| `ops-machine` | machine | client credentials | `.local/secrets/client-ops-machine` |

Other private paths: demo emails in `.local/mail-sink/` (no real email is sent), Data Protection keys in
`.local/dp-keys/`, TLS keys in `.local/tls/`. `.local/` is ignored by git and is not copied into the images.

## Walkthrough

1. `https://pano.localhost:9444` → **Sign in** → log in at Halka ID as `alice@halka.test` → consent screen → Pano.
2. Call the API on the **Workspace** page (Pano does not give the access token to the browser; it makes the call from the server).
3. `https://rapor.localhost:9445` → **Sign in**: no password is asked for (SSO), only consent for Rapor is requested.
4. `https://id.halka.localhost:9443/manage`: sessions, connected applications, MFA enrollment (QR + recovery codes).
5. Revoke a session or an application's consent; Pano / Rapor drop the session on the next request.
6. Log in as `admin@halka.test` → MFA enrollment is mandatory → `/admin`: users, sessions, grants, client
   registration (the secret is shown once), secret rotation, signing key rotation, audit log.
7. New account: **Create account** → the confirmation link is in the JSON file under `.local/mail-sink/`.

## Tests and verification

```powershell
dotnet restore Halka.slnx --locked-mode
./scripts/test.ps1 -Project Unit           # unit tests
./scripts/test.ps1 -Project Integration    # real Kestrel + Testcontainers PostgreSQL, protocol/security
./scripts/test.ps1 -Project E2E            # real browser with the installed Chrome, axe accessibility
./scripts/smoke.ps1                        # HTTPS, restarts, DB/OP outage in a separate Compose project
./scripts/scan.ps1                         # secret / authorship / dependency / container scan
./scripts/verify.ps1                       # all of the above, on a single source state
```

Linux / CI equivalent (the same steps as `.github/workflows/ci.yml`):

```bash
dotnet restore Halka.slnx --locked-mode
dotnet build Halka.slnx -c Release --no-restore
dotnet test --project tests/Halka.UnitTests -c Release --no-build
dotnet test --project tests/Halka.IntegrationTests -c Release --no-build
dotnet test --project tests/Halka.E2E -c Release --no-build
(cd src/Halka.Iam/ui-tooling && npm ci && npm run check)
```

Tests write only to disposable databases they create themselves (explicit permission + ownership marker + server
identity check); they do not touch the development stack or another project's database.

Remote CI: [run 38183758695](https://github.com/TCoderr/enterprise-identity-access-platform/actions/runs/38183758695) on commit `e7542a4`
completed successfully (`build-and-test` and the six `images` jobs; checked 2026-10-12, UTC+3). The statement is tied to that commit: no
result is claimed for later commits, including the one that adds this text. Current state:
[GitHub Actions](https://github.com/TCoderr/enterprise-identity-access-platform/actions).

The results and source fingerprints in `docs/final-verification.md` are local results and belong to the source state that was used during
that verification, before the repository was pushed (its "remote CI was not run" statement describes that moment). Commit `e7542a4` came
later: it added the English translation of this README (Turkish text in `README.tr.md`) and changed the Docker image names in
`.github/workflows/ci.yml`; application code did not change. No local re-run of the tests is on record for that commit, and because the
fingerprint script excludes only `docs/` and `artifacts/`, the fingerprint of the current tree is not one of the recorded values. The
recorded results are therefore not results for the current fingerprint; the change is covered by the remote run above.

## Repository structure

```
src/Halka.Iam            identity provider (Razor Pages, protocol, sessions, MFA, administration)
src/Halka.DemoClient     shared client library of Pano and Rapor (OIDC, server-side session)
src/Halka.Pano, Rapor    demo clients
src/Halka.WorkspaceApi   protected API
src/Halka.MachineDemo    machine client
src/Halka.Migrator       schema / roles / seed
src/Halka.Shared         shared infrastructure (secret files, backchannel, security headers, logging)
tools/Halka.LocalInit    creation of .local/ (CA, certificates, secrets, seed)
tests/                   TestKit, UnitTests, IntegrationTests, E2E, Smoke
deploy/                  Dockerfile, docker-compose.yml, .env.example
scripts/                 local-stack, test, smoke, scan, verify, source-fingerprint
docs/                    design documents, ADRs, verification reports
design/preview.html      static design preview
```

## Documentation

| Document | Contents |
|---|---|
| `docs/01`–`09` | Requirements, protocol flows, architecture, database, API/client contracts, threat model, UI design, implementation and test plan |
| `docs/adr/` | Architecture decision records |
| `docs/security-verification.md` | Test mapping of the security acceptance contract |
| `docs/revocation-matrix.md` | Which event revokes what, how quickly, and which test proves it |
| `docs/final-verification.md` | Final verification gates, commands, counts |
| `docs/known-limitations.md` | Deliberate exclusions and open limitations |
| `docs/portfolio-summary.md` | Short portfolio summary |
| `THIRD-PARTY-NOTICES.md` | Third-party components and their licenses |

## License

The source code is owned by TCoderr; no separate open-source license has been chosen for this repository. Third-party
components are subject to their own licenses (`THIRD-PARTY-NOTICES.md`).
