# Cirreum.Authentication.SignedRequest.Client 1.0.0 — Renamed outbound client SDK

## Why this release exists

The companion server-side scheme handler `Cirreum.Authorization.SignedRequest` is renamed to `Cirreum.Authentication.SignedRequest` — signed-request signing and validation prove caller identity, which is authentication. This client-SDK package follows suit — `Cirreum.Authorization.SignedRequest.Client` → `Cirreum.Authentication.SignedRequest.Client`.

The rename is the only meaningful change in this release. The source-level public surface is identical.

## What's new

Nothing new — this is a rename release. All types and extension methods carry forward unchanged.

## What's preserved

- `HttpRequestMessage.SignRequestAsync(...)` — sign outgoing requests with HMAC-SHA256 + timestamp
- `HttpClient.SendSignedAsync(...)` — fluent send-with-signing, including JSON content overloads
- `HttpRequest.ValidateSignatureAsync(...)` / `ValidateSignatureOrThrowAsync(...)` — webhook receiver validation
- `SignedRequestValidator` — standalone validator usable outside ASP.NET Core
- `SigningCredentials`, `SigningOptions`, `ValidationOptions` — configuration types

## Namespace strategy

The extension types continue to live under `System.Net.Http` and `Microsoft.AspNetCore.Http` rather than `Cirreum.Authentication.SignedRequest`. This is intentional — webhook receivers can write `request.ValidateSignatureAsync(...)` without an additional `using` directive. The intent is that signed-request signing feels like a native ASP.NET Core / `HttpClient` capability, not a Cirreum-specific extension.

## Compatibility

- **.NET 10.0** target.
- Zero Cirreum-internal package references — only `FrameworkReference Microsoft.AspNetCore.App`.
- Apps migrating from `Cirreum.Authorization.SignedRequest.Client` follow [`MIGRATION-v1.md`](MIGRATION-v1.md): one `<PackageReference>` change.
- Wire-format unchanged — clients signing with this package authenticate against servers running either `Cirreum.Authorization.SignedRequest` 1.x or `Cirreum.Authentication.SignedRequest` 1.0+ without changes.

## See also

- [`Cirreum.Authentication.SignedRequest`](https://github.com/cirreum/Cirreum.Authentication.SignedRequest) — server-side companion
- [`MIGRATION-v1.md`](MIGRATION-v1.md), [`CHANGELOG.md`](CHANGELOG.md)
