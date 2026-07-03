# Cirreum.Authentication.SignedRequest.Client 1.0.0 — the consumer SDK

Sign outbound HTTP requests and validate inbound webhooks as RFC 9421 HTTP Message
Signatures (RFC 9530 `Content-Digest`). The full-duplex client counterpart to the
server-side `Cirreum.Authentication.SignedRequest` scheme — built on the same shared
`Cirreum.SignedRequest` primitives, so what you sign here verifies byte-identically
there, and vice versa.

Strictly additive — initial release.

---

## Why this release exists

A consumer integrating with a SignedRequest-protected API needs two things: to **sign
outbound** calls (and the webhooks it sends), and to **validate inbound** webhooks it
receives. This SDK provides both, without pulling in the server-side scheme or
`Cirreum.AuthenticationProvider` — its only dependency is the dependency-free
`Cirreum.SignedRequest` primitives package.

Because the signer is the shared one from `Cirreum.SignedRequest`, a request signed
with this SDK reconstructs to the byte-identical RFC 9421 signature base a server
verifies against — the two cannot drift.

---

## What's new

### Sign outbound requests

```csharp
using var client = new HttpClient { BaseAddress = new Uri("https://api.partner.example") };

// Sign + send with a JSON body in one call:
var response = await client.SendSignedAsync(
    HttpMethod.Post, "/v1/events",
    keyId: "my-app", signingSecret: signingSecret,
    content: new { eventType = "order.placed", id = orderId });

// Or sign a prepared request:
await request.SignRequestAsync(keyId, signingSecret);
```

`HttpRequestMessage.SignRequestAsync(...)` / `HttpClient.SendSignedAsync(...)` add the
RFC 9421 `Signature` / `Signature-Input` and RFC 9530 `Content-Digest` headers. These
extensions (with `OutboundSigningOptions` and `SigningCredentials`) come from the shared
`Cirreum.SignedRequest` package and surface ambiently under `System.Net.Http`.
`OutboundSigningOptions` controls the algorithm, covered components, signature label,
`expires` window, nonce (≥ 128-bit), and audience `tag`. Sign as the **last** mutation
before sending.

### Validate inbound webhooks (ASP.NET Core)

```csharp
app.MapPost("/webhooks/partner", async (HttpRequest request, IConfiguration config) => {
    var result = await request.ValidateSignatureAsync(config["Partner:SigningSecret"]!);
    return result.IsValid ? Results.Ok() : Results.Unauthorized();
    // request.GetSignedRequestKeyId() identifies which credential signed it.
});
```

`ValidateSignatureAsync(...)` / `ValidateSignatureOrThrowAsync(...)` on `HttpRequest`,
plus `GetSignedRequestKeyId(...)` / `GetSignedRequestNonce(...)`. `ValidationOptions`
controls the timestamp tolerance (default 2 min), future-skew window (default 30 s),
the required covered components, an optional replay-claim hook, and an expected
audience `tag`.

### Validate outside ASP.NET Core

```csharp
var validator = new SignedRequestValidator(ValidationOptions.Default);
var result = validator.Validate(
    body: bodyBytes, signatureInput: signatureInputHeader, signature: signatureHeader,
    contentDigest: contentDigestHeader, httpMethod: "POST", path: "/v1/events",
    query: "", signingSecret: signingSecret);
```

`SignedRequestValidator` + `SignatureValidationResult` verify the signature, `created` /
`expires` freshness, and the `Content-Digest` body binding with no ASP.NET dependency.
Single-use nonce replay tracking is opt-in via `ValidationOptions.ReplayClaim` (it needs
a store).

---

## Wire format

The default covered set is `@method`, `@path`, `@query`, `content-digest`. The credential
is identified by the RFC 9421 `keyid` parameter — there are no custom `X-*` headers.

---

## Compatibility

- **Strictly additive.** Initial release.
- **Depends on `Cirreum.SignedRequest 1.0.0`** (the shared RFC 9421 / RFC 9530 primitives
  + outbound signer). No dependency on the server-side scheme or `Cirreum.AuthenticationProvider`.
- **.NET 10.0**; uses `FrameworkReference Microsoft.AspNetCore.App` for the webhook-receiver
  helpers.

---

## See also

- `Cirreum.SignedRequest` — the shared, dependency-free RFC 9421 / RFC 9530 primitives + signer
- `Cirreum.Authentication.SignedRequest` — the server-side scheme (verify inbound, sign outbound webhooks)
