namespace System.Net.Http;

using Cirreum.SignedRequest;
using System.Text;

/// <summary>
/// Validates incoming RFC 9421 signed HTTP requests (webhooks). Stateless: it verifies the signature,
/// freshness (<c>created</c>/<c>expires</c>), and the <c>Content-Digest</c> body binding via the shared §8
/// builder. Replay protection (single-use <c>nonce</c>) requires a store and is the receiver's
/// responsibility — this validator does not track nonces.
/// </summary>
/// <param name="options">Validation options. If null, defaults are used.</param>
public sealed class SignedRequestValidator(ValidationOptions? options = null) {

	private const string HmacSha256 = "hmac-sha256";

	private readonly ValidationOptions _options = options ?? ValidationOptions.Default;

	/// <summary>
	/// Validates a signed request from its RFC 9421 headers, request line, and body.
	/// </summary>
	/// <param name="body">The raw request body bytes.</param>
	/// <param name="signatureInput">The <c>Signature-Input</c> header value.</param>
	/// <param name="signature">The <c>Signature</c> header value.</param>
	/// <param name="contentDigest">The <c>Content-Digest</c> header value (RFC 9530).</param>
	/// <param name="httpMethod">The HTTP method.</param>
	/// <param name="path">The absolute request path (percent-encoded).</param>
	/// <param name="query">The query string including the leading <c>?</c> (empty for no query).</param>
	/// <param name="signingSecret">The signing secret to validate against.</param>
	public SignatureValidationResult Validate(
		ReadOnlySpan<byte> body,
		string? signatureInput,
		string? signature,
		string? contentDigest,
		string httpMethod,
		string path,
		string query,
		string signingSecret) {

		ArgumentException.ThrowIfNullOrWhiteSpace(httpMethod);
		ArgumentException.ThrowIfNullOrWhiteSpace(signingSecret);

		if (!SignatureWireParser.TryParse(signatureInput, signature, out var entries) || entries.Count != 1) {
			return SignatureValidationResult.Failed("Malformed or ambiguous Signature / Signature-Input headers.");
		}

		var entry = entries[0];

		foreach (var required in this._options.RequiredCoveredComponents) {
			if (!entry.CoveredComponents.Contains(required)) {
				return SignatureValidationResult.Failed($"Signature does not cover required component '{required}'.");
			}
		}

		if (!string.Equals(entry.Algorithm, HmacSha256, StringComparison.Ordinal)) {
			return SignatureValidationResult.Failed($"Unsupported signature algorithm '{entry.Algorithm}'.");
		}

		var freshness = this.ValidateFreshness(entry.Created, entry.Expires);
		if (!freshness.IsValid) {
			return freshness;
		}

		var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
		if (!string.IsNullOrEmpty(contentDigest)) {
			fields[SignatureComponentNames.ContentDigest] = contentDigest;
		}

		var components = SignatureBaseComponents.FromRequest(httpMethod, path, query, fields);

		byte[] signatureBase;
		try {
			signatureBase = SignatureBaseBuilder.BuildBase(components, entry.CoveredComponents, entry.SignatureParamsValue);
		} catch (InvalidOperationException ex) {
			return SignatureValidationResult.Failed(ex.Message);
		}

		if (!new HmacSha256SignedRequestAlgorithm().Verify(signatureBase, entry.Signature, Encoding.UTF8.GetBytes(signingSecret))) {
			return SignatureValidationResult.Failed("Signature mismatch.");
		}

		if (entry.CoveredComponents.Contains(SignatureComponentNames.ContentDigest) && !ContentDigest.Verify(contentDigest, body)) {
			return SignatureValidationResult.Failed("Content-Digest does not match the request body.");
		}

		return SignatureValidationResult.Success();
	}

	/// <summary>Validates only the freshness of a signature's <c>created</c> time.</summary>
	public SignatureValidationResult ValidateTimestamp(long created) => this.ValidateFreshness(created, expires: null);

	private SignatureValidationResult ValidateFreshness(long created, long? expires) {
		var now = DateTimeOffset.UtcNow;
		var createdTime = DateTimeOffset.FromUnixTimeSeconds(created);

		var age = now - createdTime;
		if (age > this._options.TimestampTolerance) {
			return SignatureValidationResult.Failed(
				$"Signature is too old. Age: {age.TotalSeconds:F0}s, max: {this._options.TimestampTolerance.TotalSeconds:F0}s.");
		}

		if (createdTime > now + this._options.FutureTimestampTolerance) {
			return SignatureValidationResult.Failed(
				$"Signature created time is too far in the future. Allowed skew: {this._options.FutureTimestampTolerance.TotalSeconds:F0}s.");
		}

		if (expires is { } expiresSeconds) {
			var expiresTime = DateTimeOffset.FromUnixTimeSeconds(expiresSeconds);
			if (now > expiresTime) {
				return SignatureValidationResult.Failed("Signature has expired.");
			}

			if (expiresTime - createdTime > this._options.TimestampTolerance + this._options.FutureTimestampTolerance) {
				return SignatureValidationResult.Failed("Declared validity exceeds the allowed window.");
			}
		}

		return SignatureValidationResult.Success();
	}
}
