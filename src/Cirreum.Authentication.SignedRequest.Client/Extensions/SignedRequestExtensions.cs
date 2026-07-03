namespace System.Net.Http;

using Cirreum.SignedRequest;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

/// <summary>
/// Extension methods for signing outbound HTTP requests as RFC 9421 HTTP Message Signatures (RFC 9530
/// <c>Content-Digest</c> for the body). The signing base is built with the shared <c>SignatureBaseBuilder</c>
/// (ADR-0021 §8), so a client-signed request verifies byte-identically on the server. Uses C# extension blocks.
/// </summary>
public static class SignedRequestExtensions {

	/// <summary>Extension block for <see cref="HttpRequestMessage"/> signing.</summary>
	extension(HttpRequestMessage request) {

		/// <summary>Signs the request, adding <c>Content-Digest</c>, <c>Signature-Input</c>, and <c>Signature</c> headers.</summary>
		public Task<HttpRequestMessage> SignRequestAsync(
			string keyId,
			string signingSecret,
			SigningOptions? options = null,
			CancellationToken cancellationToken = default) =>
			SignCoreAsync(request, keyId, signingSecret, options ?? SigningOptions.Default, cancellationToken);

		/// <summary>Signs the request using the supplied credentials.</summary>
		public Task<HttpRequestMessage> SignRequestAsync(
			SigningCredentials credentials,
			SigningOptions? options = null,
			CancellationToken cancellationToken = default) {

			ArgumentNullException.ThrowIfNull(credentials);
			return SignCoreAsync(request, credentials.KeyId, credentials.SigningSecret, options ?? SigningOptions.Default, cancellationToken);
		}
	}

	/// <summary>Extension block for <see cref="HttpClient"/> signed sends.</summary>
	extension(HttpClient client) {

		/// <summary>Signs and sends a request.</summary>
		public async Task<HttpResponseMessage> SendSignedAsync(
			HttpRequestMessage request,
			string keyId,
			string signingSecret,
			SigningOptions? options = null,
			CancellationToken cancellationToken = default) {

			ArgumentNullException.ThrowIfNull(request);
			// Resolve a relative RequestUri against the client's BaseAddress BEFORE signing, so the signer
			// signs the SAME absolute wire path HttpClient will actually send (otherwise @path omits the
			// BaseAddress prefix and never verifies on the server).
			ResolveAgainstBaseAddress(request, client.BaseAddress);
			await SignCoreAsync(request, keyId, signingSecret, options ?? SigningOptions.Default, cancellationToken).ConfigureAwait(false);
			return await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
		}

		/// <summary>Signs and sends a request using the supplied credentials.</summary>
		public Task<HttpResponseMessage> SendSignedAsync(
			HttpRequestMessage request,
			SigningCredentials credentials,
			SigningOptions? options = null,
			CancellationToken cancellationToken = default) {

			ArgumentNullException.ThrowIfNull(credentials);
			return client.SendSignedAsync(request, credentials.KeyId, credentials.SigningSecret, options, cancellationToken);
		}

		/// <summary>Signs and sends a request with a JSON body.</summary>
		public Task<HttpResponseMessage> SendSignedAsync<TContent>(
			HttpMethod method,
			string requestUri,
			string keyId,
			string signingSecret,
			TContent? content = default,
			SigningOptions? options = null,
			CancellationToken cancellationToken = default) {

			var request = new HttpRequestMessage(method, requestUri);

			if (content is not null) {
				var json = JsonSerializer.Serialize(
					content, (options ?? SigningOptions.Default).JsonSerializerOptions ?? SigningOptions.DefaultJsonOptions);
				request.Content = new StringContent(json, Encoding.UTF8, "application/json");
			}

			return client.SendSignedAsync(request, keyId, signingSecret, options, cancellationToken);
		}

		/// <summary>Signs and sends a request with a JSON body using the supplied credentials.</summary>
		public Task<HttpResponseMessage> SendSignedAsync<TContent>(
			HttpMethod method,
			string requestUri,
			SigningCredentials credentials,
			TContent? content = default,
			SigningOptions? options = null,
			CancellationToken cancellationToken = default) {

			ArgumentNullException.ThrowIfNull(credentials);
			return client.SendSignedAsync(method, requestUri, credentials.KeyId, credentials.SigningSecret, content, options, cancellationToken);
		}
	}

	private static async Task<HttpRequestMessage> SignCoreAsync(
		HttpRequestMessage request,
		string keyId,
		string signingSecret,
		SigningOptions options,
		CancellationToken cancellationToken) {

		ArgumentNullException.ThrowIfNull(request);
		ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
		ArgumentException.ThrowIfNullOrWhiteSpace(signingSecret);
		// Refuse to emit a signature under a sub-floor key — fail fast at the signer rather than ship a weak MAC (E3).
		SignedRequestSecret.EnsureFloor(signingSecret, nameof(signingSecret));

		// The signer must sign the exact absolute wire path. A relative RequestUri cannot be resolved here (the
		// HttpClient.BaseAddress prefix is not visible), so a relative target would silently sign an under-bound
		// @path. SendSignedAsync resolves against BaseAddress first; the request-only SignRequestAsync cannot.
		if (request.RequestUri is not { IsAbsoluteUri: true }) {
			throw new InvalidOperationException(
				"SignRequestAsync requires an absolute RequestUri. A relative URI cannot be resolved to the wire " +
				"path the server signs over. Use SendSignedAsync (which resolves against HttpClient.BaseAddress) " +
				"or set an absolute RequestUri before signing.");
		}

		if (!string.Equals(options.Algorithm, HmacSha256SignedRequestAlgorithm.Id, StringComparison.Ordinal)) {
			throw new NotSupportedException($"Signing algorithm '{options.Algorithm}' is not supported (v1 ships hmac-sha256).");
		}

		var body = request.Content is null
			? []
			: await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
		var contentDigest = ContentDigest.Compute(body);

		// RequestUri is guaranteed absolute by the guard above, so AbsolutePath/Query are already the isolated,
		// percent-encoded wire components.
		var uri = request.RequestUri!;
		var components = SignatureBaseComponents.FromRequest(
			request.Method.Method,
			uri.AbsolutePath,
			uri.Query,
			[new KeyValuePair<string, string>(SignatureComponentNames.ContentDigest, contentDigest)]);

		var created = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
		long? expires = options.ExpiresAfter is { } window ? created + (long)window.TotalSeconds : null;
		var nonce = options.IncludeNonce
			? Convert.ToBase64String(RandomNumberGenerator.GetBytes(options.NonceBytes))
			: null;

		var parameters = new SignatureParameters {
			CoveredComponents = options.CoveredComponents,
			KeyId = keyId,
			Algorithm = options.Algorithm,
			Created = created,
			Expires = expires,
			Nonce = nonce,
			Tag = options.Tag,
		};

		var result = SignatureBaseBuilder.BuildForSigning(components, parameters);
		var signature = new HmacSha256SignedRequestAlgorithm().Sign(result.SignatureBase, Encoding.UTF8.GetBytes(signingSecret));

		request.Headers.Remove("Content-Digest");
		request.Headers.Remove("Signature-Input");
		request.Headers.Remove("Signature");
		request.Headers.TryAddWithoutValidation("Content-Digest", contentDigest);
		request.Headers.TryAddWithoutValidation("Signature-Input", $"{options.SignatureLabel}={result.SignatureParamsValue}");
		request.Headers.TryAddWithoutValidation("Signature", $"{options.SignatureLabel}=:{Convert.ToBase64String(signature)}:");

		return request;
	}

	// Resolve a relative RequestUri against the client's BaseAddress so the signer signs the absolute wire path
	// HttpClient will actually send. Mirrors HttpClient's own relative-resolution; a relative URI with no
	// BaseAddress is unsignable (the wire path is unknowable) and fails fast.
	private static void ResolveAgainstBaseAddress(HttpRequestMessage request, Uri? baseAddress) {
		if (request.RequestUri is { IsAbsoluteUri: false } relative) {
			request.RequestUri = baseAddress is not null
				? new Uri(baseAddress, relative)
				: throw new InvalidOperationException(
					"Cannot sign a request with a relative RequestUri when HttpClient.BaseAddress is not set. " +
					"Set BaseAddress or use an absolute RequestUri.");
		}
	}
}
