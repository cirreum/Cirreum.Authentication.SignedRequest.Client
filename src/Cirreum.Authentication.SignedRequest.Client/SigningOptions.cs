namespace System.Net.Http;

using Cirreum.SignedRequest;
using System.Text.Json;

/// <summary>
/// Options for signing outbound HTTP requests as RFC 9421 HTTP Message Signatures.
/// </summary>
public sealed class SigningOptions {

	/// <summary>A fresh default instance (a new object each access, so a caller mutating it can't bleed config into others) (F2).</summary>
	public static SigningOptions Default => new();

	/// <summary>The shared camelCase JSON options applied to a JSON body when <see cref="JsonSerializerOptions"/> is null.</summary>
	public static JsonSerializerOptions DefaultJsonOptions { get; } = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

	/// <summary>The RFC 9421 algorithm identifier to sign with. Default <c>hmac-sha256</c> (the only v1 algorithm), bound to the shared constant (F4).</summary>
	public string Algorithm { get; set; } = HmacSha256SignedRequestAlgorithm.Id;

	/// <summary>
	/// The covered components to sign. Default <c>@method</c>, <c>@path</c>, <c>@query</c>, <c>content-digest</c>
	/// (host-independent — no <c>@authority</c>, per ADR-0021).
	/// </summary>
	public IReadOnlyList<string> CoveredComponents { get; set; } = [
		SignatureComponentNames.Method,
		SignatureComponentNames.Path,
		SignatureComponentNames.Query,
		SignatureComponentNames.ContentDigest,
	];

	/// <summary>The signature label used in the <c>Signature</c> / <c>Signature-Input</c> dictionaries. Default <c>sig1</c>.</summary>
	public string SignatureLabel { get; set; } = "sig1";

	/// <summary>When set, the signature carries an <c>expires</c> of <c>created + ExpiresAfter</c>.</summary>
	public TimeSpan? ExpiresAfter { get; set; }

	/// <summary>Whether to emit a random <c>nonce</c> parameter (required by a verifier's strict-nonce posture). Default <see langword="true"/>.</summary>
	public bool IncludeNonce { get; set; } = true;

	/// <summary>The minimum nonce size in bytes (128-bit) accepted for <see cref="NonceBytes"/>.</summary>
	public const int MinimumNonceBytes = 16;

	private int _nonceBytes = MinimumNonceBytes;

	/// <summary>
	/// The number of cryptographically-random bytes in the generated nonce. Default 16 (128-bit). Must be at
	/// least <see cref="MinimumNonceBytes"/> — a nonce below 128 bits cannot give meaningful replay protection,
	/// so a smaller value is rejected rather than silently emitting a weak nonce the server would refuse.
	/// </summary>
	public int NonceBytes {
		get => this._nonceBytes;
		set => this._nonceBytes = value >= MinimumNonceBytes
			? value
			: throw new ArgumentOutOfRangeException(nameof(value), value, $"NonceBytes must be at least {MinimumNonceBytes} (128-bit).");
	}

	/// <summary>The optional explicit audience (<c>tag</c>) — required only when the credential is bound to one.</summary>
	public string? Tag { get; set; }

	/// <summary>The JSON serializer options for a JSON request body. When null, <see cref="DefaultJsonOptions"/> (camelCase) is used — so an explicit null no longer flips to STJ PascalCase defaults (F3).</summary>
	public JsonSerializerOptions? JsonSerializerOptions { get; set; }
}
