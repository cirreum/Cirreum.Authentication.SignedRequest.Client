# Migration to Cirreum.Authentication.SignedRequest.Client v1.0

**From:** `Cirreum.Authorization.SignedRequest.Client 1.0.x` (now deprecated)
**To:** `Cirreum.Authentication.SignedRequest.Client 1.0.0`

## Why v1

`Cirreum.Authentication.SignedRequest.Client` is the renamed successor to the deprecated `Cirreum.Authorization.SignedRequest.Client`. The rename re-classifies the package under the Authentication pillar — signed-request signing/validation proves caller identity, which is authentication.

This package is **outbound only** — clients signing HTTP requests and webhook receivers validating inbound signed requests. The companion server-side scheme handler ships separately as `Cirreum.Authentication.SignedRequest`.

## Breaking Changes — Find/Replace Table

| Before | After |
|---|---|
| `<PackageReference Include="Cirreum.Authorization.SignedRequest.Client" ... />` | `<PackageReference Include="Cirreum.Authentication.SignedRequest.Client" ... />` |

**Source-level surface is identical.** The extension types continue to live under `System.Net.Http` and `Microsoft.AspNetCore.Http` namespaces, so client code that already used `request.SignRequestAsync(...)` or `request.ValidateSignatureAsync(...)` does not change.

## What Didn't Change

- All public types: `SignedRequestValidator`, `SignatureValidationResult`, `SigningCredentials`, `SigningOptions`, `ValidationOptions`
- All extension methods: `HttpRequestMessage.SignRequestAsync`, `HttpClient.SendSignedAsync`, `HttpRequest.ValidateSignatureAsync`, `HttpRequest.ValidateSignatureOrThrowAsync`, `HttpRequest.GetSignedRequestClientId`
- Canonical input shape: `{timestamp}.{method}.{path}.{bodyHash}`
- Header names: `X-Client-Id`, `X-Timestamp`, `X-Signature`
- Signature format: `v1={hexstring}` (HMAC-SHA256)
- Replay protection via timestamp tolerance

## Migration Walkthrough

1. **Update `<PackageReference>`** in your csproj — replace `Cirreum.Authorization.SignedRequest.Client` with `Cirreum.Authentication.SignedRequest.Client` at version `1.0.0`.
2. **Rebuild.** No source changes required.

## Downstream Package Impact

- **`Cirreum.Authentication.SignedRequest`** — companion server-side scheme handler, also renamed.
