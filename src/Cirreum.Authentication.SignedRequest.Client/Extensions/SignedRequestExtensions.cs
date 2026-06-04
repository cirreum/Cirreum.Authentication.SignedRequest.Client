namespace System.Net.Http;

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

/// <summary>
/// Extension methods for signing HTTP requests with HMAC signatures.
/// Uses C# 14 extension blocks for cleaner syntax.
/// </summary>
public static class SignedRequestExtensions {

	/// <summary>
	/// SHA256 hash of an empty string. Used for requests without a body.
	/// </summary>
	public const string EmptyBodyHash =
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

	/// <summary>
	/// Default header name for the client ID.
	/// </summary>
	public const string DefaultClientIdHeader = "X-Client-Id";

	/// <summary>
	/// Default header name for the timestamp.
	/// </summary>
	public const string DefaultTimestampHeader = "X-Timestamp";

	/// <summary>
	/// Default header name for the signature.
	/// </summary>
	public const string DefaultSignatureHeader = "X-Signature";

	/// <summary>
	/// Extension block for HttpRequestMessage signing operations.
	/// </summary>
	extension(HttpRequestMessage request) {

		/// <summary>
		/// Signs the request by adding X-Client-Id, X-Timestamp, and X-Signature headers.
		/// </summary>
		/// <param name="clientId">The public client identifier.</param>
		/// <param name="signingSecret">The secret key used for HMAC signature.</param>
		/// <param name="options">Optional signing options.</param>
		/// <param name="cancellationToken">Cancellation token.</param>
		/// <returns>The request for chaining.</returns>
		public async Task<HttpRequestMessage> SignRequestAsync(
			string clientId,
			string signingSecret,
			SigningOptions? options = null,
			CancellationToken cancellationToken = default) {

			ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
			ArgumentException.ThrowIfNullOrWhiteSpace(signingSecret);

			options ??= SigningOptions.Default;

			var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
			var bodyHash = await ComputeBodyHashAsync(request.Content, cancellationToken).ConfigureAwait(false);
			var path = GetRequestPath(request.RequestUri, options.IncludeQueryString);
			var method = request.Method.Method.ToUpperInvariant();

			var canonicalRequest = $"{timestamp}.{method}.{path}.{bodyHash}";
			var signature = ComputeSignature(canonicalRequest, signingSecret, options.SignatureVersion);

			request.Headers.Remove(options.ClientIdHeaderName);
			request.Headers.Remove(options.TimestampHeaderName);
			request.Headers.Remove(options.SignatureHeaderName);

			request.Headers.TryAddWithoutValidation(options.ClientIdHeaderName, clientId);
			request.Headers.TryAddWithoutValidation(options.TimestampHeaderName, timestamp.ToString());
			request.Headers.TryAddWithoutValidation(options.SignatureHeaderName, signature);

			return request;
		}

		/// <summary>
		/// Signs the request by adding X-Client-Id, X-Timestamp, and X-Signature headers.
		/// </summary>
		/// <param name="credentials">The signing credentials.</param>
		/// <param name="options">Optional signing options.</param>
		/// <param name="cancellationToken">Cancellation token.</param>
		/// <returns>The request for chaining.</returns>
		public Task<HttpRequestMessage> SignRequestAsync(
			SigningCredentials credentials,
			SigningOptions? options = null,
			CancellationToken cancellationToken = default) {

			ArgumentNullException.ThrowIfNull(credentials);
			return request.SignRequestAsync(credentials.ClientId, credentials.SigningSecret, options, cancellationToken);
		}
	}

	/// <summary>
	/// Extension block for HttpClient signed request operations.
	/// </summary>
	extension(HttpClient client) {

		/// <summary>
		/// Sends a signed HTTP request.
		/// </summary>
		/// <param name="request">The request to sign and send.</param>
		/// <param name="clientId">The public client identifier.</param>
		/// <param name="signingSecret">The secret key used for HMAC signature.</param>
		/// <param name="options">Optional signing options.</param>
		/// <param name="cancellationToken">Cancellation token.</param>
		/// <returns>The HTTP response.</returns>
		public async Task<HttpResponseMessage> SendSignedAsync(
			HttpRequestMessage request,
			string clientId,
			string signingSecret,
			SigningOptions? options = null,
			CancellationToken cancellationToken = default) {

			await request.SignRequestAsync(clientId, signingSecret, options, cancellationToken).ConfigureAwait(false);
			return await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
		}

		/// <summary>
		/// Sends a signed HTTP request.
		/// </summary>
		/// <param name="request">The request to sign and send.</param>
		/// <param name="credentials">The signing credentials.</param>
		/// <param name="options">Optional signing options.</param>
		/// <param name="cancellationToken">Cancellation token.</param>
		/// <returns>The HTTP response.</returns>
		public Task<HttpResponseMessage> SendSignedAsync(
			HttpRequestMessage request,
			SigningCredentials credentials,
			SigningOptions? options = null,
			CancellationToken cancellationToken = default) {

			ArgumentNullException.ThrowIfNull(credentials);
			return client.SendSignedAsync(request, credentials.ClientId, credentials.SigningSecret, options, cancellationToken);
		}

		/// <summary>
		/// Sends a signed HTTP request with JSON content.
		/// </summary>
		/// <typeparam name="TContent">The type of the request body.</typeparam>
		/// <param name="method">The HTTP method.</param>
		/// <param name="requestUri">The request URI.</param>
		/// <param name="clientId">The public client identifier.</param>
		/// <param name="signingSecret">The secret key used for HMAC signature.</param>
		/// <param name="content">The request body (will be serialized to JSON).</param>
		/// <param name="options">Optional signing options.</param>
		/// <param name="cancellationToken">Cancellation token.</param>
		/// <returns>The HTTP response.</returns>
		public Task<HttpResponseMessage> SendSignedAsync<TContent>(
			HttpMethod method,
			string requestUri,
			string clientId,
			string signingSecret,
			TContent? content = default,
			SigningOptions? options = null,
			CancellationToken cancellationToken = default) {

			var request = new HttpRequestMessage(method, requestUri);

			if (content is not null) {
				var json = JsonSerializer.Serialize(content, options?.JsonSerializerOptions);
				request.Content = new StringContent(json, Encoding.UTF8, "application/json");
			}

			return client.SendSignedAsync(request, clientId, signingSecret, options, cancellationToken);
		}

		/// <summary>
		/// Sends a signed HTTP request with JSON content.
		/// </summary>
		/// <typeparam name="TContent">The type of the request body.</typeparam>
		/// <param name="method">The HTTP method.</param>
		/// <param name="requestUri">The request URI.</param>
		/// <param name="credentials">The signing credentials.</param>
		/// <param name="content">The request body (will be serialized to JSON).</param>
		/// <param name="options">Optional signing options.</param>
		/// <param name="cancellationToken">Cancellation token.</param>
		/// <returns>The HTTP response.</returns>
		public Task<HttpResponseMessage> SendSignedAsync<TContent>(
			HttpMethod method,
			string requestUri,
			SigningCredentials credentials,
			TContent? content = default,
			SigningOptions? options = null,
			CancellationToken cancellationToken = default) {

			ArgumentNullException.ThrowIfNull(credentials);
			return client.SendSignedAsync(method, requestUri, credentials.ClientId, credentials.SigningSecret, content, options, cancellationToken);
		}
	}

	private static async Task<string> ComputeBodyHashAsync(HttpContent? content, CancellationToken cancellationToken) {
		if (content is null) {
			return EmptyBodyHash;
		}

		var bytes = await content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);

		if (bytes.Length == 0) {
			return EmptyBodyHash;
		}

		var hash = SHA256.HashData(bytes);
		return Convert.ToHexString(hash).ToLowerInvariant();
	}

	private static string GetRequestPath(Uri? uri, bool includeQueryString) {
		if (uri is null) {
			return "/";
		}

		string path;
		string query;

		if (uri.IsAbsoluteUri) {
			path = uri.AbsolutePath;
			query = uri.Query;
		} else {
			var originalString = uri.OriginalString;
			var queryIndex = originalString.IndexOf('?');
			if (queryIndex >= 0) {
				path = originalString[..queryIndex];
				query = originalString[queryIndex..];
			} else {
				path = originalString;
				query = string.Empty;
			}
		}

		if (string.IsNullOrEmpty(path)) {
			path = "/";
		}

		if (includeQueryString && !string.IsNullOrEmpty(query)) {
			path += query;
		}

		return path;
	}

	private static string ComputeSignature(string canonicalRequest, string signingSecret, string version) {
		var keyBytes = Encoding.UTF8.GetBytes(signingSecret);
		var messageBytes = Encoding.UTF8.GetBytes(canonicalRequest);

		var hmac = HMACSHA256.HashData(keyBytes, messageBytes);
		var signatureValue = Convert.ToHexString(hmac).ToLowerInvariant();

		return $"{version}={signatureValue}";
	}
}
