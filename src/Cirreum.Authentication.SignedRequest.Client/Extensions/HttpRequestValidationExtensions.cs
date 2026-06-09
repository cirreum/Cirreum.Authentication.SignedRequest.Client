namespace Microsoft.AspNetCore.Http;

using Cirreum.SignedRequest;
using System.Net.Http;

/// <summary>
/// Extension methods for validating incoming RFC 9421 signed HTTP requests (webhooks) in ASP.NET Core.
/// </summary>
public static class HttpRequestValidationExtensions {

	/// <summary>
	/// Validates a signed webhook request: reads <c>Signature</c>/<c>Signature-Input</c>/<c>Content-Digest</c>,
	/// the request line, and the body, and verifies them against <paramref name="signingSecret"/>.
	/// </summary>
	public static async Task<SignatureValidationResult> ValidateSignatureAsync(
		this HttpRequest request,
		string signingSecret,
		ValidationOptions? options = null,
		CancellationToken cancellationToken = default) {

		ArgumentNullException.ThrowIfNull(request);
		ArgumentException.ThrowIfNullOrWhiteSpace(signingSecret);

		options ??= ValidationOptions.Default;

		var signatureInput = request.Headers["Signature-Input"].ToString();
		var signature = request.Headers["Signature"].ToString();
		var contentDigest = request.Headers["Content-Digest"].ToString();

		if (string.IsNullOrEmpty(signatureInput) && string.IsNullOrEmpty(signature)) {
			return SignatureValidationResult.Failed("Missing Signature / Signature-Input headers.");
		}

		if (!request.Body.CanSeek) {
			request.EnableBuffering();
		}

		var originalPosition = request.Body.Position;
		try {
			request.Body.Position = 0;
			using var memoryStream = new MemoryStream();
			await request.Body.CopyToAsync(memoryStream, cancellationToken).ConfigureAwait(false);
			var body = memoryStream.GetBuffer().AsSpan(0, (int)memoryStream.Length);

			var validator = new SignedRequestValidator(options);
			return validator.Validate(
				body,
				signatureInput,
				signature,
				contentDigest,
				request.Method,
				request.Path.ToUriComponent(),
				request.QueryString.Value ?? string.Empty,
				signingSecret);
		} finally {
			request.Body.Position = originalPosition;
		}
	}

	/// <summary>Validates a signed webhook request and throws if invalid.</summary>
	/// <exception cref="InvalidOperationException">Thrown when validation fails.</exception>
	public static async Task ValidateSignatureOrThrowAsync(
		this HttpRequest request,
		string signingSecret,
		ValidationOptions? options = null,
		CancellationToken cancellationToken = default) {

		var result = await request.ValidateSignatureAsync(signingSecret, options, cancellationToken).ConfigureAwait(false);
		result.ThrowIfInvalid();
	}

	/// <summary>
	/// Gets the credential identifier (<c>keyid</c>) from a signed request's <c>Signature-Input</c>, or
	/// <see langword="null"/> if the signature headers are absent or malformed.
	/// </summary>
	public static string? GetSignedRequestKeyId(this HttpRequest request) {
		ArgumentNullException.ThrowIfNull(request);

		var signatureInput = request.Headers["Signature-Input"].ToString();
		var signature = request.Headers["Signature"].ToString();

		return SignatureWireParser.TryParse(signatureInput, signature, out var entries) && entries.Count > 0
			? entries[0].KeyId
			: null;
	}
}
