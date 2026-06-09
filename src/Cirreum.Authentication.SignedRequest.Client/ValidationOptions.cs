namespace System.Net.Http;

using Cirreum.SignedRequest;

/// <summary>
/// Options for validating incoming RFC 9421 signed requests (webhooks).
/// </summary>
public sealed class ValidationOptions {

	/// <summary>Default validation options.</summary>
	public static ValidationOptions Default { get; } = new();

	/// <summary>
	/// The maximum age of a signature's <c>created</c> time before it is rejected (replay window). Default 5 minutes.
	/// </summary>
	public TimeSpan TimestampTolerance { get; set; } = TimeSpan.FromMinutes(5);

	/// <summary>How far a signature's <c>created</c> time may be in the future (clock skew). Default 1 minute.</summary>
	public TimeSpan FutureTimestampTolerance { get; set; } = TimeSpan.FromMinutes(1);

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
}
