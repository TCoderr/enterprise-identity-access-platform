# Third-Party Notices

Halka ID (author and owner: TCoderr) uses the third-party components listed below. Each component remains under
its own license and copyright; nothing here changes those terms. License identifiers were read from the package
metadata of the exact versions pinned in `Directory.Packages.props`, the lock files and
`src/Halka.Iam/ui-tooling/package-lock.json`. Transitive dependencies are listed in the `packages.lock.json` file
of each project and carry their own notices inside their packages.

No third-party source code is copied into this repository. Components are consumed as unmodified packages or
container images.

## Shipped with the applications (runtime)

| Component | Version | License | Copyright / author |
|---|---|---|---|
| .NET runtime and ASP.NET Core (`Microsoft.AspNetCore.*`, `Microsoft.Extensions.*`) | 10.0.12 | MIT | .NET Foundation and Contributors, Microsoft |
| Entity Framework Core (`Microsoft.EntityFrameworkCore.*`) | 10.0.12 | MIT | .NET Foundation and Contributors, Microsoft |
| ASP.NET Core Identity (`Microsoft.AspNetCore.Identity.EntityFrameworkCore`) | 10.0.12 | MIT | Microsoft |
| `Microsoft.AspNetCore.Authentication.OpenIdConnect` | 10.0.12 | MIT | Microsoft |
| `Microsoft.AspNetCore.OpenApi` | 10.0.12 | MIT | Microsoft |
| Microsoft IdentityModel (`Microsoft.IdentityModel.*`, `System.IdentityModel.Tokens.Jwt`) | 8.19.2 | MIT | Microsoft |
| OpenIddict (`OpenIddict.AspNetCore`, `OpenIddict.EntityFrameworkCore`, `OpenIddict.Validation.*`) | 7.7.2 | Apache-2.0 | Kévin Chalet |
| Npgsql and `Npgsql.EntityFrameworkCore.PostgreSQL` | 10.0.3 | PostgreSQL License | The Npgsql Development Team (Shay Rojansky, Austin Drenski, Yoh Deadfall and contributors) |
| `EFCore.NamingConventions` | 10.0.1 | Apache-2.0 | Shay Rojansky |
| Otp.NET | 1.4.1 | MIT | Kyle Spearrin |
| QRCoder | 1.8.0 | MIT | Raffael Herrmann, Shane Krueger |

## Container images (local stack)

| Image | Use | License |
|---|---|---|
| `mcr.microsoft.com/dotnet/sdk:10.0.401` | build stage only | MIT (.NET); the image contains further components under their own licenses |
| `mcr.microsoft.com/dotnet/aspnet:10.0.12` | runtime base image | MIT (.NET); the image contains further components under their own licenses |
| `postgres:17-alpine` | database | PostgreSQL License (PostgreSQL), Alpine Linux packages under their own licenses |

## Development and test only (not shipped)

| Component | Version | License | Copyright / author |
|---|---|---|---|
| xUnit.net v3 (`xunit.v3`) | 4.0.2 | Apache-2.0 | .NET Foundation, James Newkirk, Brad Wilson |
| Testcontainers for .NET (`Testcontainers.PostgreSql`) | 4.16.0 | MIT | Andre Hofmeister and contributors |
| AngleSharp | 1.8.4 | MIT | AngleSharp contributors |
| `Microsoft.Extensions.TimeProvider.Testing` | 10.10.0 | MIT | Microsoft |
| Playwright for .NET (`Microsoft.Playwright`) | 1.63.0 | MIT | Microsoft |
| `Deque.AxeCore.Playwright` | 4.13.0 | MIT (the bundled axe-core engine is MPL-2.0) | Deque Systems |
| `Microsoft.EntityFrameworkCore.Design`, `dotnet-ef` | 10.0.12 | MIT | Microsoft |
| TypeScript | 7.0.2 | Apache-2.0 | Microsoft |
| ESLint, `@eslint/js` | 10.12.0, 10.0.1 | MIT | OpenJS Foundation and contributors |

## Standards

The protocol behaviour follows public specifications (OAuth 2.0 RFC 6749, PKCE RFC 7636, token revocation RFC 7009,
introspection RFC 7662, OAuth security best current practice RFC 9700, OpenID Connect Core and Discovery, TOTP
RFC 6238). They are implemented through the libraries above; no specification text is reproduced here. The project
has not been run against the OpenID Foundation conformance suite and makes no certification claim.

## Design and accessibility sources

No external design, front-end or accessibility "skill" package, template or component library was installed or
copied. The design system is a small hand-written stylesheet in this repository (`src/Halka.Iam/wwwroot/site.css`,
described in `docs/07-ui-design.md`). Accessibility checks use axe-core through `Deque.AxeCore.Playwright` (listed
above) at test time only.

## Fonts, icons and other assets

The user interface uses system font stacks only and loads nothing from other origins. The favicons and the
stylesheet were written for this project.
