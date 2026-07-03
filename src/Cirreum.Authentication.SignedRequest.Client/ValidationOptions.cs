namespace System.Net.Http;

using Cirreum.SignedRequest;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Options for validating incoming RFC 9421 signed requests (webhooks) in the consumer SDK.
/// </summary>
public sealed class ValidationOptions {

	/// <summary>
	/// A fresh default instance. Returns a new object each access (the option object is mutable, so a shared
	/// singleton would invite cross-call configuration bleed and a System.Text.Json freeze foot-gun) (F2).
	/// </summary>
	public static ValidationOptions Default => new();

	/// <summary>
	/// The maximum age of a signature's <c>created</c> time before it is rejected (the freshness / replay
	/// window). Default 2 minutes — aligned to the server handler so the standalone webhook surface is not the
	/// looser one (B1). A receiver with genuinely slower webhook delivery may raise this knowingly; pair a wider
	/// window with <see cref="ReplayClaim"/> so a captured request is not replayable for the whole window.
	/// </summary>
	public TimeSpan TimestampTolerance { get; set; } = TimeSpan.FromMinutes(2);

	/// <summary>How far a signature's <c>created</c> time may be in the future (clock skew). Default 30 seconds (aligned to the server).</summary>
	public TimeSpan FutureTimestampTolerance { get; set; } = TimeSpan.FromSeconds(30);

	/// <summary>
	/// The covered components a signature MUST include; a signature that omits any is rejected. Default
	/// <c>@method</c>, <c>@path</c>, <c>@query</c>, <c>content-digest</c>.
	/// </summary>
	public IReadOnlyList<string> RequiredCoveredComponents { get; set; } = [
		SignatureComponentNames.Method,
		SignatureComponentNames.Path,
		SignatureComponentNames.Query,
		SignatureComponentNames.ContentDigest,
	];

	/// <summary>
	/// The audience this receiver expects in the signed <c>tag</c> (B4). When set, a request whose signed tag does
	/// not equal this value is rejected (checked after the signature verifies, so the tag is authenticated). When
	/// <see langword="null"/> the tag is not checked. Set this when validating credentials deliberately shared
	/// across more than one audience.
	/// </summary>
	public string? ExpectedTag { get; set; }

	/// <summary>
	/// When <see langword="true"/>, the signature must carry a <c>nonce</c> of at least
	/// <see cref="MinimumNonceLength"/> characters or the request is rejected (B2). Default <see langword="false"/>.
	/// </summary>
	public bool RequireNonce { get; set; }

	/// <summary>The minimum accepted <c>nonce</c> length in characters under <see cref="RequireNonce"/> / <see cref="ReplayClaim"/>. Default 22 (≈128 bits at base64 density).</summary>
	public int MinimumNonceLength { get; set; } = 22;

	/// <summary>
	/// Opt-in single-use replay protection (B2). When set, the nonce is atomically claimed via this delegate
	/// AFTER the signature verifies; returning <see langword="false"/> (the nonce was already seen) fails the
	/// request closed, and a throwing delegate also fails closed. The receiver owns the seen-nonce store — this is
	/// the SDK-side analog of the server handler's strict-nonce <c>IReplayGuard</c>. When <see langword="null"/>,
	/// no claim is made (the receiver can still enforce replay out-of-band via <c>GetSignedRequestNonce</c>).
	/// </summary>
	public Func<string, CancellationToken, ValueTask<bool>>? ReplayClaim { get; set; }
}
