namespace System.Net.Http;

using System.Text.Json;

/// <summary>
/// Options for signing HTTP requests.
/// </summary>
public sealed class SigningOptions {

	/// <summary>
	/// Default signing options.
	/// </summary>
	public static SigningOptions Default { get; } = new();

	/// <summary>
	/// Gets or sets the signature version. Default is "v1".
	/// </summary>
	public string SignatureVersion { get; set; } = "v1";

	/// <summary>
	/// Gets or sets whether to include the query string in the signature. Default is true.
	/// </summary>
	public bool IncludeQueryString { get; set; } = true;

	/// <summary>
	/// Gets or sets the header name for the client ID. Default is "X-Client-Id".
	/// </summary>
	public string ClientIdHeaderName { get; set; } = SignedRequestExtensions.DefaultClientIdHeader;

	/// <summary>
	/// Gets or sets the header name for the timestamp. Default is "X-Timestamp".
	/// </summary>
	public string TimestampHeaderName { get; set; } = SignedRequestExtensions.DefaultTimestampHeader;

	/// <summary>
	/// Gets or sets the header name for the signature. Default is "X-Signature".
	/// </summary>
	public string SignatureHeaderName { get; set; } = SignedRequestExtensions.DefaultSignatureHeader;

	/// <summary>
	/// Gets or sets the JSON serializer options for request bodies. Default uses camelCase.
	/// </summary>
	public JsonSerializerOptions? JsonSerializerOptions { get; set; } = new() {
		PropertyNamingPolicy = JsonNamingPolicy.CamelCase
	};
}
