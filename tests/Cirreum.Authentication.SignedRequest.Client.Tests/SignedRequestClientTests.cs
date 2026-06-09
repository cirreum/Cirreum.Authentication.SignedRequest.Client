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
		await request.SignRequestAsync(KeyId, Secret, new SigningOptions {
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

	// --- ⑦ NonceBytes below 128-bit is rejected at configuration time (no silent weak nonce). ---

	[Fact]
	public void NonceBytes_below_128_bit_is_rejected() {
		var act = () => new SigningOptions { NonceBytes = 8 };

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
