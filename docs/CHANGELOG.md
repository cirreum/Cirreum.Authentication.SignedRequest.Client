# Cirreum.Authentication.SignedRequest.Client Changelog

All notable changes to **Cirreum.Authentication.SignedRequest.Client** are documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) — [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- Initial release. Cirreum.Authentication.SignedRequest.Client is the outbound client SDK for the SignedRequest authentication scheme — the companion to the server-side `Cirreum.Authentication.SignedRequest` package.
- **Renamed and re-homed from the deprecated `Cirreum.Authorization.SignedRequest.Client`** — signed-request signing and validation prove caller identity, which is authentication. Source surface is unchanged; the rename is purely a re-classification under the Authentication pillar.
- Surface preserved from 1.0.x of the predecessor package:
  - `SignedRequestExtensions` — `HttpRequestMessage.SignRequestAsync(...)`, `HttpClient.SendSignedAsync(...)` (with `JsonSerializer` overload)
  - `SignedRequestValidator` + `SignatureValidationResult` for webhook validation
  - `SigningCredentials`, `SigningOptions`, `ValidationOptions`
  - `HttpRequestValidationExtensions` — `HttpRequest.ValidateSignatureAsync(...)`, `ValidateSignatureOrThrowAsync(...)`, `GetSignedRequestClientId(...)` for ASP.NET Core webhook receivers
- Namespace strategy preserved: extension types live under `System.Net.Http` and `Microsoft.AspNetCore.Http` so they surface as if they're built into the platform — no `using Cirreum.Authentication.SignedRequest;` required in consumer code.

### Migration

Apps consuming `Cirreum.Authorization.SignedRequest.Client` migrate by installing `Cirreum.Authentication.SignedRequest.Client`. The source-level surface is identical; only the package reference name changes. The old `Cirreum.Authorization.SignedRequest.Client` package deprecates on NuGet with a successor message pointing here. See [`docs/MIGRATION-v1.md`](MIGRATION-v1.md).
