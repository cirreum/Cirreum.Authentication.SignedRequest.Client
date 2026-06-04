# Cirreum Authentication - SignedRequest Client SDK

[![NuGet Version](https://img.shields.io/nuget/v/Cirreum.Authentication.SignedRequest.Client.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Authentication.SignedRequest.Client/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Cirreum.Authentication.SignedRequest.Client.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Authentication.SignedRequest.Client/)
[![GitHub Release](https://img.shields.io/github/v/release/cirreum/Cirreum.Authentication.SignedRequest.Client?style=flat-square&labelColor=1F1F1F&color=FF3B2E)](https://github.com/cirreum/Cirreum.Authentication.SignedRequest.Client/releases)
[![License](https://img.shields.io/github/license/cirreum/Cirreum.Authentication.SignedRequest.Client?style=flat-square&labelColor=1F1F1F&color=F2F2F2)](https://github.com/cirreum/Cirreum.Authentication.SignedRequest.Client/blob/main/LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-003D8F?style=flat-square&labelColor=1F1F1F)](https://dotnet.microsoft.com/)

**Client SDK for HMAC signed request authentication**

> **Migrating from `Cirreum.Authorization.SignedRequest.Client`?** This package is its renamed successor — same surface, proper pillar. See [`docs/MIGRATION-v1.md`](docs/MIGRATION-v1.md). Update one `<PackageReference>` and rebuild.

## Overview

**Cirreum.Authentication.SignedRequest.Client** is the outbound companion to the server-side [`Cirreum.Authentication.SignedRequest`](https://github.com/cirreum/Cirreum.Authentication.SignedRequest) scheme. It provides two integration surfaces:

- **Signing outbound requests** — extension methods on `HttpRequestMessage` and `HttpClient` to sign requests with HMAC-SHA256 + timestamp
- **Validating inbound webhooks** — extension methods on ASP.NET Core `HttpRequest` to validate signed webhooks against a known secret, plus a standalone `SignedRequestValidator` usable outside ASP.NET Core

The extension types live under `System.Net.Http` and `Microsoft.AspNetCore.Http` namespaces — webhook receivers can write `request.ValidateSignatureAsync(...)` without any additional `using` directive.

## Installation

```bash
dotnet add package Cirreum.Authentication.SignedRequest.Client
```

## Signing outgoing requests

```csharp
using var client = new HttpClient { BaseAddress = new Uri("https://api.partner.example") };

var response = await client.SendSignedAsync(
    HttpMethod.Post,
    "/v1/events",
    clientId: "my-app",
    signingSecret: signingSecret,
    content: new { eventType = "order.placed", id = orderId });
```

Or sign a pre-built `HttpRequestMessage`:

```csharp
var request = new HttpRequestMessage(HttpMethod.Post, "/v1/events") {
    Content = JsonContent.Create(payload)
};
await request.SignRequestAsync(clientId, signingSecret);
var response = await client.SendAsync(request);
```

`SigningOptions` controls the version identifier, header names, JSON serializer options, and whether the query string is included in the signature.

## Validating inbound webhooks (ASP.NET Core)

```csharp
app.MapPost("/webhooks/partner", async (HttpRequest request, IConfiguration config) => {
    await request.ValidateSignatureOrThrowAsync(config["Partner:SigningSecret"]!);

    // ... handle the webhook payload
    return Results.Ok();
});
```

For non-throwing validation:

```csharp
var result = await request.ValidateSignatureAsync(signingSecret);
if (!result.IsValid) {
    return Results.Unauthorized();
}
```

`ValidationOptions` controls the timestamp tolerance, future-skew window, supported signature versions, header names, and whether the query string is included.

## Validating outside ASP.NET Core

```csharp
var validator = new SignedRequestValidator(ValidationOptions.Default);
var result = validator.Validate(
    body: bodyBytes,
    signature: signatureHeader,
    timestamp: timestamp,
    httpMethod: "POST",
    path: "/v1/events",
    signingSecret: signingSecret);
```

## Wire format

Signed requests carry three headers:

| Header | Description |
|---|---|
| `X-Client-Id` | Public client identifier; the server looks up the matching signing secret |
| `X-Timestamp` | Unix timestamp (seconds); replay protection |
| `X-Signature` | `v1={hexstring}` — HMAC-SHA256 over `{timestamp}.{method}.{path}.{bodyHash}`, lowercase hex-encoded |

`bodyHash` is the SHA-256 of the body (or the empty-body sentinel for `GET`/`HEAD`/`DELETE`/`OPTIONS`).

## Security considerations

- **Timestamp tolerance** — Default 5 minutes (validator) and 1 minute future skew. Tighten for partners with reliable clocks.
- **Signing secrets** — Treat as secrets. Rotate periodically; the signature version field supports clean rotation of the algorithm itself.
- **Transport security** — Always use HTTPS to prevent tampering of headers or body beyond the signature's scope.

## License

MIT — see [LICENSE](LICENSE).

---

**Cirreum Foundation Framework**
*Layered simplicity for modern .NET*
