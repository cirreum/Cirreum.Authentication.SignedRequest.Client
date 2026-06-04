namespace System.Net.Http;

/// <summary>
/// Options for validating incoming signed requests.
/// </summary>
public sealed class ValidationOptions {

	/// <summary>
	/// Default validation options.
	/// </summary>
	public static ValidationOptions Default { get; } = new();

	/// <summary>
	/// Gets or sets the maximum age allowed for request timestamps.
	/// Requests older than this will be rejected to prevent replay attacks.
	/// Default is 5 minutes.
	/// </summary>
	public TimeSpan TimestampTolerance { get; set; } = TimeSpan.FromMinutes(5);

	/// <summary>
	/// Gets or sets the maximum amount of time a request timestamp can be in the future.
	/// Allows for clock skew between client and server.
	/// Default is 1 minute.
	/// </summary>
	public TimeSpan FutureTimestampTolerance { get; set; } = TimeSpan.FromMinutes(1);

	/// <summary>
	/// Gets or sets the supported signature versions.
	/// Default includes only "v1".
	/// </summary>
	public HashSet<string> SupportedSignatureVersions { get; set; } = ["v1"];

	/// <summary>
	/// Gets or sets the header name for the client ID.
	/// </summary>
	public string ClientIdHeaderName { get; set; } = SignedRequestExtensions.DefaultClientIdHeader;

	/// <summary>
	/// Gets or sets the header name for the timestamp.
	/// </summary>
	public string TimestampHeaderName { get; set; } = SignedRequestExtensions.DefaultTimestampHeader;

	/// <summary>
	/// Gets or sets the header name for the signature.
	/// </summary>
	public string SignatureHeaderName { get; set; } = SignedRequestExtensions.DefaultSignatureHeader;

	/// <summary>
	/// Gets or sets whether to include the query string when validating the path.
	/// Must match the sender's configuration.
	/// Default is true.
	/// </summary>
	public bool IncludeQueryString { get; set; } = true;
}
