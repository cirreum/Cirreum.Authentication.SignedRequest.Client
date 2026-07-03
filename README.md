# Cirreum Authentication - SignedRequest Client SDK

[![NuGet Version](https://img.shields.io/nuget/v/Cirreum.Authentication.SignedRequest.Client.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Authentication.SignedRequest.Client/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Cirreum.Authentication.SignedRequest.Client.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Authentication.SignedRequest.Client/)
[![GitHub Release](https://img.shields.io/github/v/release/cirreum/Cirreum.Authentication.SignedRequest.Client?style=flat-square&labelColor=1F1F1F&color=FF3B2E)](https://github.com/cirreum/Cirreum.Authentication.SignedRequest.Client/releases)
[![License](https://img.shields.io/badge/license-MIT-F2F2F2?style=flat-square&labelColor=1F1F1F)](https://github.com/cirreum/Cirreum.Authentication.SignedRequest.Client/blob/main/LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-003D8F?style=flat-square&labelColor=1F1F1F)](https://dotnet.microsoft.com/)

**Client SDK for RFC 9421 HTTP Message Signatures — sign outbound requests, validate inbound webhooks**

## Overview

**Cirreum.Authentication.SignedRequest.Client** is the full-duplex client counterpart to the server-side [`Cirreum.Authentication.SignedRequest`](https://github.com/cirreum/Cirreum.Authentication.SignedRequest) scheme. It builds on the shared, dependency-free [`Cirreum.SignedRequest`](https://github.com/cirreum/Cirreum.SignedRequest) primitives — the same code the server uses — so what you sign here verifies byte-identically there, and vice versa. It has **no dependency on the server-side scheme or `AuthenticationProvider`.**

Two surfaces:

- **Sign outbound requests** — extension methods on `HttpRequestMessage` / `HttpClient` that add the RFC 9421 `Signature` / `Signature-Input` and RFC 9530 `Content-Digest` headers.
- **Validate inbound webhooks** — extension methods on ASP.NET Core `HttpRequest`, plus a standalone `SignedRequestValidator` for use outside ASP.NET Core.

The extension types live in the `System.Net.Http` and `Microsoft.AspNetCore.Http` namespaces, so `request.SignRequestAsync(...)` / `request.ValidateSignatureAsync(...)` are available without an extra `using`.

## Installation

```bash
dotnet add package Cirreum.Authentication.SignedRequest.Client
```

## Signing outgoing requests

```csharp
using var client = new HttpClient { BaseAddress = new Uri("https://api.partner.example") };

// Sign + send with a JSON body in one call:
var response = await client.SendSignedAsync(
    HttpMethod.Post, "/v1/events",
    keyId: "my-app",
    signingSecret: signingSecret,
    content: new { eventType = "order.placed", id = orderId });
```

Or sign a prepared `HttpRequestMessage`:

```csharp
var request = new HttpRequestMessage(HttpMethod.Post, "/v1/events") { Content = JsonContent.Create(payload) };
await request.SignRequestAsync(keyId, signingSecret);
var response = await client.SendAsync(request);
```

`OutboundSigningOptions` controls the algorithm, covered components, signature label, `expires` window, the nonce (≥ 128-bit; smaller is rejected), the audience `tag`, and JSON serialization. Sign as the **last** mutation before sending — a later handler that changes the URI, headers, or body would invalidate the signature.

## Validating inbound webhooks (ASP.NET Core)

```csharp
app.MapPost("/webhooks/partner", async (HttpRequest request, IConfiguration config) => {
    var result = await request.ValidateSignatureAsync(config["Partner:SigningSecret"]!);
    if (!result.IsValid) {
        return Results.Unauthorized();
    }

    // request.GetSignedRequestKeyId() identifies which credential signed it.
    return Results.Ok();
});
```

`ValidateSignatureOrThrowAsync(...)` is the throwing variant. `ValidationOptions` controls the timestamp tolerance (default 2 min), future-skew window (default 30 s), and the required covered components.

## Validating outside ASP.NET Core

```csharp
var validator = new SignedRequestValidator(ValidationOptions.Default);
var result = validator.Validate(
    body: bodyBytes,
    signatureInput: signatureInputHeader,
    signature: signatureHeader,
    contentDigest: contentDigestHeader,
    httpMethod: "POST",
    path: "/v1/events",
    query: "",
    signingSecret: signingSecret);
```

> The webhook validator verifies the signature, `created` / `expires` freshness, and the `Content-Digest` body binding. Single-use **nonce replay** tracking is the receiver's responsibility (it needs a store) — the stateless validator does not track nonces.

## Wire format (RFC 9421 / RFC 9530)

| Header | Description |
|---|---|
| `Signature-Input` | The covered-component list + parameters (`created`, `expires`, `nonce`, `keyid`, `alg`, `tag`) |
| `Signature` | The HMAC over the RFC 9421 signature base, as an RFC 8941 byte sequence |
| `Content-Digest` | RFC 9530 `sha-256=:…:` over the body |

The default covered set is `@method`, `@path`, `@query`, `content-digest`. The credential is identified by the `keyid` parameter — there are no custom `X-*` headers.

## RFC conformance profile

> Cirreum SignedRequest implements a constrained Cirreum profile of RFC 9421 and RFC 9530. The implementation intentionally supports the covered components, algorithms, digest forms, and validation behavior documented here; unsupported general RFC features are out of scope unless explicitly listed.

| Area | Supported | Not supported |
|---|---|---|
| Covered components | `@method`, `@path`, `@query`, HTTP fields (`content-digest`) | `@authority` (intentionally dropped), `@target-uri`, `@scheme`, `@status` (response signing), `@query-param`, component parameters (`sf` / `key` / `bs` / `req`) |
| Algorithms | `hmac-sha256` | others are additive via the shared `ISignedRequestAlgorithm` seam (e.g. Ed25519) |
| Digest (RFC 9530) | `Content-Digest` with `sha-256` | other digest algorithms (ignored), `Repr-Digest` / `Want-*-Digest` |
| Signatures per request | exactly one | multi-signature messages are rejected by the validator |
| Structured fields (RFC 8941) | the dictionary / inner-list / string / byte-sequence / integer subset these headers use | a general RFC 8941 parser |

`@path` / `@query` are normalized to the RFC 9421 §2.2.6/§2.2.7 + RFC 3986 §6.2.2 canonical form, so a request signed here validates regardless of how the receiver's host re-encodes the URL. Conformance is verified against RFC 4231 and RFC 9530 published vectors; the signature base is locked by a known-answer vector.

## Security considerations

- **Nonce** — left enabled (128-bit CSPRNG) so requests satisfy a server's strict-nonce posture; `NonceBytes` below 16 is rejected.
- **Signing secrets** — treat as secrets; ≥ 256-bit recommended. `SigningCredentials.ToString()` redacts the secret.
- **Audience** — set the `Tag` only when the target credential is bound to an audience.
- **Transport** — always use HTTPS.

## License

MIT — see [LICENSE](LICENSE).

---

**Cirreum Foundation Framework**
*Layered simplicity for modern .NET*
