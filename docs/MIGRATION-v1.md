# Cirreum.Authentication.SignedRequest.Client v1.0.0 — Migration Guide

> **From:** _(no prior version)_ &nbsp;•&nbsp; **To:** v1.0.0

## Why v1

This is the **initial release** of `Cirreum.Authentication.SignedRequest.Client`.
There is no earlier published version, so there is nothing for a consumer to migrate
from.

---

## Breaking Changes — Find/Replace Table

None. Initial release.

---

## New Capabilities

See [`docs/RELEASE-NOTES-v1.0.0.md`](RELEASE-NOTES-v1.0.0.md) for the full surface
and usage examples.

---

## Migration Walkthrough

### 1. Add the package reference

```xml
<PackageReference Include="Cirreum.Authentication.SignedRequest.Client" Version="1.0.0" />
```

The outbound-signing extensions (`HttpRequestMessage.SignRequestAsync(...)`,
`HttpClient.SendSignedAsync(...)`) and the webhook-receiver extensions
(`HttpRequest.ValidateSignatureAsync(...)`) live under the `System.Net.Http` and
`Microsoft.AspNetCore.Http` namespaces, so they surface without an extra `using`.

---

## What Didn't Change

Everything — this is the first release.

---

## Downstream Package Impact

This SDK takes a `PackageReference` on `Cirreum.SignedRequest 1.0.0` (the shared,
dependency-free RFC 9421 / RFC 9530 primitives, including the outbound signer). That
package must be published first.
