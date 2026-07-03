namespace Cirreum.Authentication.SignedRequest.Client.Tests;

using Cirreum.SignedRequest;
using Microsoft.AspNetCore.Http;
using System.Net.Http;
using System.Text;

/// <summary>
/// Round-trip proofs for the client SDK: a request signed by the outbound signer validates through the
/// standalone <see cref="SignedRequestValidator"/> and the ASP.NET webhook helper (both built on the shared
/// §8 builder), and tampering / a wrong secret / a missing required component are rejected.
/// </summary>
public sealed class SignedRequestClientTests {

	private const string KeyId = "svc-a";
	private const string Secret = "super-secret-signing-key";

	private static HttpRequestMessage NewRequest(
		string method = "POST",
		string uri = "https://api.example.com/orders?page=1",
		string? body = "{\"id\":1}") {

		var request = new HttpRequestMessage(new HttpMethod(method), uri);
		if (body is not null) {
			request.Content = new StringContent(body, Encoding.UTF8, "application/json");
		}

		return request;
	}

	private static (byte[] Body, string SignatureInput, string Signature, string ContentDigest, string Method, string Path, string Query)
		Extract(HttpRequestMessage request) {

		var body = request.Content is null ? [] : request.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
		string Header(string name) => request.Headers.TryGetValues(name, out var values) ? string.Join(",", values) : string.Empty;
		var uri = request.RequestUri!;
		return (body, Header("Signature-Input"), Header("Signature"), Header("Content-Digest"), request.Method.Method, uri.AbsolutePath, uri.Query);
	}

	[Fact]
	public async Task Sign_then_validate_round_trips() {
		var request = NewRequest();
		await request.SignRequestAsync(KeyId, Secret);

		var (body, signatureInput, signature, contentDigest, method, path, query) = Extract(request);
		var result = new SignedRequestValidator()
			.Validate(body, signatureInput, signature, contentDigest, method, path, query, Secret);

		result.IsValid.Should().BeTrue(result.ErrorMessage);
	}

	[Fact]
	public async Task Signing_with_credentials_round_trips() {
		var request = NewRequest("GET", "https://api.example.com/orders", body: null);
		await request.SignRequestAsync(new SigningCredentials(KeyId, Secret));

		var (body, signatureInput, signature, contentDigest, method, path, query) = Extract(request);
		var result = new SignedRequestValidator()
			.Validate(body, signatureInput, signature, contentDigest, method, path, query, Secret);

		result.IsValid.Should().BeTrue(result.ErrorMessage);
	}

	[Fact]
	public async Task A_tampered_body_fails_content_digest() {
		var request = NewRequest();
		await request.SignRequestAsync(KeyId, Secret);
		var (_, signatureInput, signature, contentDigest, method, path, query) = Extract(request);

		var tamperedBody = Encoding.UTF8.GetBytes("{\"id\":999}");
		var result = new SignedRequestValidator()
			.Validate(tamperedBody, signatureInput, signature, contentDigest, method, path, query, Secret);

		result.IsValid.Should().BeFalse();
		result.ErrorMessage.Should().Contain("Content-Digest");
	}

	[Fact]
	public async Task A_wrong_secret_fails() {
		var request = NewRequest();
		await request.SignRequestAsync(KeyId, Secret);
		var (body, signatureInput, signature, contentDigest, method, path, query) = Extract(request);

		var result = new SignedRequestValidator()
			.Validate(body, signatureInput, signature, contentDigest, method, path, query, "a-different-secret");

		result.IsValid.Should().BeFalse();
		result.ErrorMessage.Should().Contain("mismatch");
	}

	[Fact]
	public async Task A_signature_missing_a_required_component_fails() {
		var request = NewRequest();
		await request.SignRequestAsync(KeyId, Secret, new OutboundSigningOptions {
			CoveredComponents = ["@method", "@path", "@query"], // omits content-digest
		});
		var (body, signatureInput, signature, contentDigest, method, path, query) = Extract(request);

		var result = new SignedRequestValidator()
			.Validate(body, signatureInput, signature, contentDigest, method, path, query, Secret);

		result.IsValid.Should().BeFalse();
		result.ErrorMessage.Should().Contain("content-digest");
	}

	[Fact]
	public async Task Webhook_validation_via_HttpRequest_round_trips() {
		var request = NewRequest();
		await request.SignRequestAsync(KeyId, Secret);
		var (body, signatureInput, signature, contentDigest, method, path, query) = Extract(request);

		var context = new DefaultHttpContext();
		context.Request.Method = method;
		context.Request.Path = path;
		context.Request.QueryString = new QueryString(query);
		context.Request.Body = new MemoryStream(body, writable: false);
		context.Request.Headers["Signature-Input"] = signatureInput;
		context.Request.Headers["Signature"] = signature;
		context.Request.Headers["Content-Digest"] = contentDigest;

		var result = await context.Request.ValidateSignatureAsync(Secret);

		result.IsValid.Should().BeTrue(result.ErrorMessage);
		context.Request.GetSignedRequestKeyId().Should().Be(KeyId);
	}

	// --- ① Cross-surface parity: a request signed against an encoded / non-ASCII URL (client Uri.AbsolutePath)
	//        validates through the webhook helper (server ToUriComponent), with the receiver request
	//        reconstructed from the same wire URL exactly as Kestrel would (FromUriComponent). ---

	[Theory]
	[InlineData("https://api.example.com/files/a%20b")]            // percent-encoded space
	[InlineData("https://api.example.com/r%C3%A9sum%C3%A9")]       // percent-encoded UTF-8
	[InlineData("https://api.example.com/orders?q=a%20b&page=2")]  // encoded query
	public async Task A_signed_encoded_url_round_trips_through_the_webhook_validator(string url) {
		var request = NewRequest("POST", url);
		await request.SignRequestAsync(KeyId, Secret);
		var (body, signatureInput, signature, contentDigest, method, _, _) = Extract(request);

		// Receiver: reconstruct the ASP.NET request from the SAME wire URL exactly as Kestrel parses it.
		var uri = new Uri(url);
		var context = new DefaultHttpContext();
		context.Request.Method = method;
		context.Request.Path = PathString.FromUriComponent(uri);
		context.Request.QueryString = QueryString.FromUriComponent(uri);
		context.Request.Body = new MemoryStream(body, writable: false);
		context.Request.Headers["Signature-Input"] = signatureInput;
		context.Request.Headers["Signature"] = signature;
		context.Request.Headers["Content-Digest"] = contentDigest;

		var result = await context.Request.ValidateSignatureAsync(Secret);

		result.IsValid.Should().BeTrue(result.ErrorMessage);
	}

	// --- H1: a body the signature does not bind is rejected even when content-digest is not a required component. ---

	[Fact]
	public async Task The_validator_rejects_a_body_the_signature_does_not_bind_H1() {
		var request = NewRequest("POST", "https://api.example.com/orders", "{\"id\":1}");
		await request.SignRequestAsync(KeyId, Secret, new OutboundSigningOptions {
			CoveredComponents = ["@method", "@path", "@query"], // omits content-digest
		});
		var (body, signatureInput, signature, contentDigest, method, path, query) = Extract(request);

		// Operator dropped content-digest from the required set, so the required-component check passes — but the
		// request carries a body the signature does not bind, which must still fail closed (H1).
		var options = new ValidationOptions { RequiredCoveredComponents = ["@method", "@path", "@query"] };
		var result = new SignedRequestValidator(options)
			.Validate(body, signatureInput, signature, contentDigest, method, path, query, Secret);

		result.IsValid.Should().BeFalse();
		result.ErrorMessage.Should().Contain("does not bind");
	}

	// --- A2: relative-URI signing. SignRequestAsync (request-only) cannot resolve the wire path and throws;
	//        SendSignedAsync resolves against HttpClient.BaseAddress so @path includes the prefix. ---

	[Fact]
	public async Task Signing_a_relative_RequestUri_throws() {
		var request = new HttpRequestMessage(HttpMethod.Get, "orders?page=1"); // relative — no absolute path

		var act = () => request.SignRequestAsync(KeyId, Secret);

		await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*absolute RequestUri*");
	}

	[Fact]
	public async Task SendSigned_resolves_a_relative_uri_against_BaseAddress_and_signs_the_prefixed_path() {
		var handler = new CapturingHandler();
		using var client = new HttpClient(handler) { BaseAddress = new Uri("https://api.example.com/v1/") };
		var request = new HttpRequestMessage(HttpMethod.Get, "orders?page=1"); // relative

		await client.SendSignedAsync(request, KeyId, Secret);

		var captured = handler.Captured!;
		captured.RequestUri!.AbsolutePath.Should().Be("/v1/orders", "the BaseAddress prefix is resolved before signing");

		var (body, signatureInput, signature, contentDigest, method, path, query) = Extract(captured);
		new SignedRequestValidator()
			.Validate(body, signatureInput, signature, contentDigest, method, path, query, Secret)
			.IsValid.Should().BeTrue("the signature covers the resolved /v1/orders path");
	}

	private sealed class CapturingHandler : HttpMessageHandler {
		public HttpRequestMessage? Captured { get; private set; }

		protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
			this.Captured = request;
			return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
		}
	}

	// --- Batch 4: cross-surface hardening of the SDK validator (B1–B4) + secret generator / sign floor (E2/E3). ---

	[Fact]
	public void The_validator_default_freshness_window_is_aligned_to_the_server_B1() {
		ValidationOptions.Default.TimestampTolerance.Should().Be(TimeSpan.FromMinutes(2));
		ValidationOptions.Default.FutureTimestampTolerance.Should().Be(TimeSpan.FromSeconds(30));
	}

	[Fact]
	public async Task The_validator_rejects_a_secret_below_the_floor_B3() {
		var request = NewRequest();
		await request.SignRequestAsync(KeyId, Secret);
		var (body, signatureInput, signature, contentDigest, method, path, query) = Extract(request);

		var result = new SignedRequestValidator()
			.Validate(body, signatureInput, signature, contentDigest, method, path, query, "short"); // < 16 bytes

		result.IsValid.Should().BeFalse();
		result.ErrorMessage.Should().Contain("minimum");
	}

	[Fact]
	public async Task The_validator_enforces_the_expected_audience_tag_B4() {
		var request = NewRequest();
		await request.SignRequestAsync(KeyId, Secret, new OutboundSigningOptions { Tag = "audience-a" });
		var (body, signatureInput, signature, contentDigest, method, path, query) = Extract(request);

		new SignedRequestValidator(new ValidationOptions { ExpectedTag = "audience-a" })
			.Validate(body, signatureInput, signature, contentDigest, method, path, query, Secret)
			.IsValid.Should().BeTrue();

		var mismatched = new SignedRequestValidator(new ValidationOptions { ExpectedTag = "audience-b" })
			.Validate(body, signatureInput, signature, contentDigest, method, path, query, Secret);
		mismatched.IsValid.Should().BeFalse();
		mismatched.ErrorMessage.Should().Contain("tag");
	}

	[Fact]
	public async Task The_webhook_validator_claims_the_nonce_and_rejects_a_replay_B2() {
		var request = NewRequest();
		await request.SignRequestAsync(KeyId, Secret); // the signer emits a nonce by default
		var (body, signatureInput, signature, contentDigest, method, path, query) = Extract(request);

		var seen = new HashSet<string>();
		var options = new ValidationOptions {
			RequireNonce = true,
			ReplayClaim = (nonce, _) => ValueTask.FromResult(seen.Add(nonce)),
		};

		DefaultHttpContext Ctx() {
			var c = new DefaultHttpContext();
			c.Request.Method = method;
			c.Request.Path = path;
			c.Request.QueryString = new QueryString(query);
			c.Request.Body = new MemoryStream(body, writable: false);
			c.Request.Headers["Signature-Input"] = signatureInput;
			c.Request.Headers["Signature"] = signature;
			c.Request.Headers["Content-Digest"] = contentDigest;
			return c;
		}

		var first = await Ctx().Request.ValidateSignatureAsync(Secret, options);
		var second = await Ctx().Request.ValidateSignatureAsync(Secret, options);

		first.IsValid.Should().BeTrue(first.ErrorMessage);
		second.IsValid.Should().BeFalse("the nonce was already claimed");
		second.ErrorMessage.Should().Contain("Replay");
	}

	[Fact]
	public async Task GetSignedRequestNonce_surfaces_the_signed_nonce_B2() {
		var request = NewRequest();
		await request.SignRequestAsync(KeyId, Secret);
		var (_, signatureInput, signature, _, _, _, _) = Extract(request);
		var ctx = new DefaultHttpContext();
		ctx.Request.Headers["Signature-Input"] = signatureInput;
		ctx.Request.Headers["Signature"] = signature;

		ctx.Request.GetSignedRequestNonce().Should().NotBeNullOrEmpty();
	}

	[Fact]
	public void SigningSecretGenerator_produces_a_secret_above_the_floor_E2() {
		var secret = SigningSecretGenerator.Generate();

		SignedRequestSecret.MeetsFloor(secret).Should().BeTrue();
		secret.Should().NotContain("+").And.NotContain("/").And.NotContain("=");
	}

	[Fact]
	public async Task Signing_with_a_secret_below_the_floor_throws_E3() {
		var request = NewRequest();

		var act = () => request.SignRequestAsync(KeyId, "short"); // < 16 bytes

		await act.Should().ThrowAsync<ArgumentException>().WithMessage("*16 bytes*");
	}

	// --- ⑦ NonceBytes below 128-bit is rejected at configuration time (no silent weak nonce). ---

	[Fact]
	public void NonceBytes_below_128_bit_is_rejected() {
		var act = () => new OutboundSigningOptions { NonceBytes = 8 };

		act.Should().Throw<ArgumentOutOfRangeException>();
	}

	// --- ⑥ The credentials ToString redacts the secret (no leak through logging / interpolation). ---

	[Fact]
	public void SigningCredentials_ToString_redacts_the_secret() {
		new SigningCredentials(KeyId, Secret).ToString().Should().NotContain(Secret).And.Contain("[redacted]");
	}

	// --- Known-answer vector: the client package, built on the shared Common primitives, produces the exact
	//     RFC 9421 wire signature base the server and Common assert (cross-package parity anchor). ---

	[Fact]
	public void Known_answer_signature_base_is_byte_stable() {
		var components = SignatureBaseComponents.FromRequest(
			"POST", "/api/orders", "?page=1", [new("content-digest", "sha-256=:abc:")]);

		var parameters = new SignatureParameters {
			CoveredComponents = ["@method", "@path", "@query", "content-digest"],
			KeyId = "svc-a",
			Algorithm = "hmac-sha256",
			Created = 1_718_000_000,
			Nonce = "nonce-xyz-0123456789",
		};

		var expected =
			"\"@method\": POST\n" +
			"\"@path\": /api/orders\n" +
			"\"@query\": ?page=1\n" +
			"\"content-digest\": sha-256=:abc:\n" +
			"\"@signature-params\": (\"@method\" \"@path\" \"@query\" \"content-digest\")" +
			";created=1718000000;keyid=\"svc-a\";alg=\"hmac-sha256\";nonce=\"nonce-xyz-0123456789\"";

		Encoding.UTF8.GetString(SignatureBaseBuilder.BuildForSigning(components, parameters).SignatureBase)
			.Should().Be(expected);
	}
}
