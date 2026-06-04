namespace System.Net.Http;

using System.Security.Cryptography;
using System.Text;

/// <summary>
/// Validates incoming signed HTTP requests (webhooks).
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="SignedRequestValidator"/> class.
/// </remarks>
/// <param name="options">Validation options. If null, defaults are used.</param>
public sealed class SignedRequestValidator(ValidationOptions? options = null) {

	private readonly ValidationOptions _options = options ?? ValidationOptions.Default;

	/// <summary>
	/// Validates a signed request.
	/// </summary>
	/// <param name="body">The raw request body bytes.</param>
	/// <param name="signature">The signature header value (e.g., "v1=abc123...").</param>
	/// <param name="timestamp">The Unix timestamp from the request.</param>
	/// <param name="httpMethod">The HTTP method (GET, POST, etc.).</param>
	/// <param name="path">The request path including query string if applicable.</param>
	/// <param name="signingSecret">The signing secret to validate against.</param>
	/// <returns>A validation result indicating success or failure.</returns>
	public SignatureValidationResult Validate(
		ReadOnlySpan<byte> body,
		string signature,
		long timestamp,
		string httpMethod,
		string path,
		string signingSecret) {

		ArgumentException.ThrowIfNullOrWhiteSpace(signature);
		ArgumentException.ThrowIfNullOrWhiteSpace(httpMethod);
		ArgumentException.ThrowIfNullOrWhiteSpace(path);
		ArgumentException.ThrowIfNullOrWhiteSpace(signingSecret);

		// 1. Validate timestamp
		var timestampResult = this.ValidateTimestamp(timestamp);
		if (!timestampResult.IsValid) {
			return timestampResult;
		}

		// 2. Parse signature
		var signatureParts = signature.Split('=', 2);
		if (signatureParts.Length != 2) {
			return SignatureValidationResult.Failed("Invalid signature format. Expected 'version=signature'.");
		}

		var version = signatureParts[0];
		var providedSignature = signatureParts[1];

		if (!this._options.SupportedSignatureVersions.Contains(version)) {
			return SignatureValidationResult.Failed($"Unsupported signature version: {version}");
		}

		// 3. Compute body hash
		var bodyHash = ComputeBodyHash(body);

		// 4. Build canonical request and compute expected signature
		var method = httpMethod.ToUpperInvariant();
		var canonicalRequest = $"{timestamp}.{method}.{path}.{bodyHash}";
		var expectedSignature = ComputeSignatureValue(canonicalRequest, signingSecret);

		// 5. Constant-time comparison
		var providedBytes = Encoding.UTF8.GetBytes(providedSignature.ToLowerInvariant());
		var expectedBytes = Encoding.UTF8.GetBytes(expectedSignature.ToLowerInvariant());

		if (!CryptographicOperations.FixedTimeEquals(providedBytes, expectedBytes)) {
			return SignatureValidationResult.Failed("Signature mismatch.");
		}

		return SignatureValidationResult.Success();
	}

	/// <summary>
	/// Validates a signed request.
	/// </summary>
	/// <param name="body">The raw request body bytes.</param>
	/// <param name="signature">The signature header value.</param>
	/// <param name="timestamp">The Unix timestamp from the request.</param>
	/// <param name="httpMethod">The HTTP method.</param>
	/// <param name="path">The request path.</param>
	/// <param name="signingSecret">The signing secret.</param>
	/// <returns>A validation result.</returns>
	public SignatureValidationResult Validate(
		byte[] body,
		string signature,
		long timestamp,
		string httpMethod,
		string path,
		string signingSecret) {

		return this.Validate(body.AsSpan(), signature, timestamp, httpMethod, path, signingSecret);
	}

	/// <summary>
	/// Validates only the timestamp portion of a signed request.
	/// </summary>
	/// <param name="timestamp">The Unix timestamp to validate.</param>
	/// <returns>A validation result.</returns>
	public SignatureValidationResult ValidateTimestamp(long timestamp) {
		var requestTime = DateTimeOffset.FromUnixTimeSeconds(timestamp);
		var now = DateTimeOffset.UtcNow;

		// Check if timestamp is too old
		var age = now - requestTime;
		if (age > this._options.TimestampTolerance) {
			return SignatureValidationResult.Failed(
				$"Timestamp is too old. Age: {age.TotalSeconds:F0}s, Max: {this._options.TimestampTolerance.TotalSeconds:F0}s");
		}

		// Check if timestamp is too far in the future (clock skew)
		if (requestTime > now + this._options.FutureTimestampTolerance) {
			return SignatureValidationResult.Failed(
				$"Timestamp is too far in the future. Allowed skew: {this._options.FutureTimestampTolerance.TotalSeconds:F0}s");
		}

		return SignatureValidationResult.Success();
	}

	/// <summary>
	/// Computes the SHA256 hash of the body.
	/// </summary>
	/// <param name="body">The body bytes.</param>
	/// <returns>The lowercase hex-encoded hash.</returns>
	public static string ComputeBodyHash(ReadOnlySpan<byte> body) {
		if (body.IsEmpty) {
			return SignedRequestExtensions.EmptyBodyHash;
		}

		Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
		SHA256.HashData(body, hash);
		return Convert.ToHexString(hash).ToLowerInvariant();
	}

	private static string ComputeSignatureValue(string canonicalRequest, string signingSecret) {
		var keyBytes = Encoding.UTF8.GetBytes(signingSecret);
		var messageBytes = Encoding.UTF8.GetBytes(canonicalRequest);

		var hmac = HMACSHA256.HashData(keyBytes, messageBytes);
		return Convert.ToHexString(hmac).ToLowerInvariant();
	}
}
