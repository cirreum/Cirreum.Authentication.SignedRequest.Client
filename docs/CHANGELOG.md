# Cirreum.Authentication.SignedRequest.Client Changelog

All notable changes to **Cirreum.Authentication.SignedRequest.Client** are documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) — [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [1.0.0] - 2026-07-03

### Added

- Initial release. Cirreum.Authentication.SignedRequest.Client is the outbound client SDK for the SignedRequest authentication scheme — the companion to the server-side `Cirreum.Authentication.SignedRequest` package. Signs outbound requests and validates inbound webhooks as RFC 9421 HTTP Message Signatures (RFC 9530 `Content-Digest`), with no dependency on the server-side scheme or `Cirreum.AuthenticationProvider`.
- Outbound signing — `HttpRequestMessage.SignRequestAsync(...)` / `HttpClient.SendSignedAsync(...)` (with `JsonSerializer` overload), `OutboundSigningOptions`, and `SigningCredentials` — is provided by the shared, dependency-free `Cirreum.SignedRequest` package (the single signer used by both this SDK and the server scheme, so a client-signed request verifies byte-identically server-side). Referencing this SDK surfaces those extensions ambiently.
- Webhook-receiver surface (this package):
  - `SignedRequestValidator` + `SignatureValidationResult` for standalone webhook validation
  - `ValidationOptions` (freshness, required components, replay hook, expected `tag`)
  - `HttpRequestValidationExtensions` — `HttpRequest.ValidateSignatureAsync(...)`, `ValidateSignatureOrThrowAsync(...)`, `GetSignedRequestKeyId(...)`, `GetSignedRequestNonce(...)` for ASP.NET Core webhook receivers
- Namespace strategy: extension types live under `System.Net.Http` and `Microsoft.AspNetCore.Http` so they surface as if they're built into the platform — no `using Cirreum.Authentication.SignedRequest;` required in consumer code.
