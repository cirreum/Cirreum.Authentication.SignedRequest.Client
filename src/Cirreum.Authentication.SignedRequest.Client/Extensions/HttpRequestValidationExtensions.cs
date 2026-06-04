namespace Microsoft.AspNetCore.Http;

using System.Net.Http;

/// <summary>
/// Extension methods for validating signed HTTP requests in ASP.NET Core.
/// </summary>
public static class HttpRequestValidationExtensions {

	/// <summary>
	/// Validates a signed webhook request.
	/// </summary>
	/// <param name="request">The incoming HTTP request.</param>
	/// <param name="signingSecret">The signing secret to validate against.</param>
	/// <param name="options">Optional validation options.</param>
	/// <param name="cancellationToken">Cancellation token.</param>
	/// <returns>A validation result indicating success or failure.</returns>
	public static async Task<SignatureValidationResult> ValidateSignatureAsync(
		this HttpRequest request,
		string signingSecret,
		ValidationOptions? options = null,
		CancellationToken cancellationToken = default) {

		ArgumentNullException.ThrowIfNull(request);
		ArgumentException.ThrowIfNullOrWhiteSpace(signingSecret);

		options ??= ValidationOptions.Default;

		// Extract headers
		var signature = request.Headers[options.SignatureHeaderName].FirstOrDefault();
		var timestampStr = request.Headers[options.TimestampHeaderName].FirstOrDefault();

		if (string.IsNullOrEmpty(signature)) {
			return SignatureValidationResult.Failed($"Missing {options.SignatureHeaderName} header.");
		}

		if (string.IsNullOrEmpty(timestampStr) || !long.TryParse(timestampStr, out var timestamp)) {
			return SignatureValidationResult.Failed($"Missing or invalid {options.TimestampHeaderName} header.");
		}

		// Read body
		if (!request.Body.CanSeek) {
			request.EnableBuffering();
		}

		var originalPosition = request.Body.Position;
		try {
			request.Body.Position = 0;
			using var memoryStream = new MemoryStream();
			await request.Body.CopyToAsync(memoryStream, cancellationToken).ConfigureAwait(false);
			var body = memoryStream.GetBuffer().AsSpan(0, (int)memoryStream.Length);

			// Build path
			var path = options.IncludeQueryString
				? request.Path + request.QueryString
				: request.Path.ToString();

			// Validate
			var validator = new SignedRequestValidator(options);
			return validator.Validate(body, signature, timestamp, request.Method, path, signingSecret);
		} finally {
			request.Body.Position = originalPosition;
		}
	}

	/// <summary>
	/// Validates a signed webhook request and throws if invalid.
	/// </summary>
	/// <param name="request">The incoming HTTP request.</param>
	/// <param name="signingSecret">The signing secret to validate against.</param>
	/// <param name="options">Optional validation options.</param>
	/// <param name="cancellationToken">Cancellation token.</param>
	/// <exception cref="InvalidOperationException">Thrown when validation fails.</exception>
	public static async Task ValidateSignatureOrThrowAsync(
		this HttpRequest request,
		string signingSecret,
		ValidationOptions? options = null,
		CancellationToken cancellationToken = default) {

		var result = await request.ValidateSignatureAsync(signingSecret, options, cancellationToken)
			.ConfigureAwait(false);

		result.ThrowIfInvalid();
	}

	/// <summary>
	/// Gets the client ID from a signed request.
	/// </summary>
	/// <param name="request">The incoming HTTP request.</param>
	/// <param name="options">Optional validation options for header name configuration.</param>
	/// <returns>The client ID, or null if not present.</returns>
	public static string? GetSignedRequestClientId(
		this HttpRequest request,
		ValidationOptions? options = null) {

		ArgumentNullException.ThrowIfNull(request);

		var headerName = options?.ClientIdHeaderName ?? SignedRequestExtensions.DefaultClientIdHeader;
		return request.Headers[headerName].FirstOrDefault();
	}
}
