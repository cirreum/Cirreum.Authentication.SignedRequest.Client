# Migration to Cirreum.Authentication.SignedRequest.Client v1.0

> **From:** `Cirreum.Authorization.SignedRequest.Client 1.0.x` (now deprecated) &nbsp;•&nbsp; **To:** `Cirreum.Authentication.SignedRequest.Client 1.0.0`

## ⚠️ This is a breaking protocol change, not a drop-in rename

`Cirreum.Authentication.SignedRequest.Client` is the renamed **and re-designed** successor to the
deprecated `Cirreum.Authorization.SignedRequest.Client`. Two things changed together:

1. **The pillar rename** — the package moved from the Authorization pillar to Authentication, so the
   package id and (for the outbound-signing types) their home package change.
2. **The wire format is now genuinely RFC 9421 / RFC 9530** — the previous custom-header envelope
   (`X-Client-Id` / `X-Timestamp` / `X-Signature`) is **gone**. `SignRequestAsync(...)` /
   `SendSignedAsync(...)` now emit RFC 9421 `Signature` / `Signature-Input` + RFC 9530 `Content-Digest`.

**A request signed with this SDK will not authenticate against a server still running the legacy
`Cirreum.Authorization.SignedRequest` verifier, and vice versa.** Upgrade the client SDK and the
server scheme (`Cirreum.Authentication.SignedRequest`) together.

## Breaking Changes — Find/Replace Table

| Before (`Cirreum.Authorization.SignedRequest.Client`) | After (`Cirreum.Authentication.SignedRequest.Client`) |
|---|---|
| `<PackageReference Include="Cirreum.Authorization.SignedRequest.Client" .../>` | `<PackageReference Include="Cirreum.Authentication.SignedRequest.Client" Version="1.0.0" />` |
| `SigningOptions` | `OutboundSigningOptions` (now provided by the shared `Cirreum.SignedRequest` package) |
| legacy custom-header signature | RFC 9421 `Signature` / `Signature-Input` + RFC 9530 `Content-Digest` |

The method names `HttpRequestMessage.SignRequestAsync(...)`, `HttpClient.SendSignedAsync(...)`, and
`HttpRequest.ValidateSignatureAsync(...)` are unchanged and still surface ambiently under
`System.Net.Http` / `Microsoft.AspNetCore.Http` — but what they produce / accept on the wire is now RFC 9421.

## What Didn't Change

- The extension-method entry points and their namespaces (no extra `using` needed).
- HMAC-SHA256 as the signing algorithm; the shared secret model.

## Downstream Package Impact

- Outbound signing (`SignRequestAsync` / `SendSignedAsync`, `OutboundSigningOptions`, `SigningCredentials`)
  now comes from the shared **`Cirreum.SignedRequest`** package — the same signer the server scheme uses,
  so a client-signed request verifies byte-identically server-side.
- Pair this SDK with `Cirreum.Authentication.SignedRequest 1.0.0` (the RFC 9421 server verifier).
