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
				var json = JsonSerializer.Serialize(content, (options ?? SigningOptions.Default).JsonSerializerOptions);
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

		if (!string.Equals(options.Algorithm, HmacSha256SignedRequestAlgorithm.Id, StringComparison.Ordinal)) {
			throw new NotSupportedException($"Signing algorithm '{options.Algorithm}' is not supported (v1 ships hmac-sha256).");
		}

		var body = request.Content is null
			? []
			: await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
		var contentDigest = ContentDigest.Compute(body);

		var (path, query) = GetPathAndQuery(request.RequestUri);
		var components = SignatureBaseComponents.FromRequest(
			request.Method.Method,
			path,
			query,
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

	private static (string Path, string Query) GetPathAndQuery(Uri? uri) {
		if (uri is null) {
			return ("/", string.Empty);
		}

		if (uri.IsAbsoluteUri) {
			return (uri.AbsolutePath, uri.Query);
		}

		var original = uri.OriginalString;
		var queryIndex = original.IndexOf('?');
		return queryIndex >= 0 ? (original[..queryIndex], original[queryIndex..]) : (original, string.Empty);
	}
}
