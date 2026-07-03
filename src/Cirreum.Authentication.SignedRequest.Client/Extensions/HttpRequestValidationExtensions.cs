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

		SignatureValidationResult result;
		var originalPosition = request.Body.Position;
		try {
			request.Body.Position = 0;
			using var memoryStream = new MemoryStream();
			await request.Body.CopyToAsync(memoryStream, cancellationToken).ConfigureAwait(false);
			var body = memoryStream.GetBuffer().AsSpan(0, (int)memoryStream.Length);

			result = new SignedRequestValidator(options).Validate(
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

		if (!result.IsValid) {
			return result;
		}

		// B2: opt-in single-use replay protection, applied only after the signature (and body) verify.
		return await ApplyReplayProtectionAsync(signatureInput, signature, options, cancellationToken).ConfigureAwait(false)
			?? result;
	}

	// Returns a failure result on a replay problem (missing/weak/seen nonce, or a throwing store), or null when
	// replay protection is not requested or the nonce was newly claimed (B2).
	private static async Task<SignatureValidationResult?> ApplyReplayProtectionAsync(
		string signatureInput, string signature, ValidationOptions options, CancellationToken cancellationToken) {

		if (!options.RequireNonce && options.ReplayClaim is null) {
			return null;
		}

		var nonce = TryGetNonce(signatureInput, signature);
		if (string.IsNullOrEmpty(nonce)) {
			return options.RequireNonce
				? SignatureValidationResult.Failed("A nonce is required but the signature carries none.")
				: null;
		}

		if (nonce.Length < options.MinimumNonceLength) {
			return SignatureValidationResult.Failed("The nonce is shorter than the required minimum.");
		}

		if (options.ReplayClaim is null) {
			return null; // RequireNonce satisfied (present + long enough); no store configured to claim against.
		}

		bool claimed;
		try {
			claimed = await options.ReplayClaim(nonce, cancellationToken).ConfigureAwait(false);
		} catch (Exception ex) when (ex is not OperationCanceledException) {
			// Backend unreachable — fail closed, not open.
			_ = ex;
			return SignatureValidationResult.Failed("Replay protection backend is unavailable.");
		}

		return claimed ? null : SignatureValidationResult.Failed("Replayed signed request.");
	}

	private static string? TryGetNonce(string signatureInput, string signature) =>
		SignatureWireParser.TryParse(signatureInput, signature, out var entries) && entries.Count == 1
			? entries[0].Nonce
			: null;

	/// <summary>
	/// Gets the <c>nonce</c> from a signed request's <c>Signature-Input</c>, or <see langword="null"/> when the
	/// signature headers are absent/malformed or carry no nonce. Lets a webhook receiver enforce single-use replay
	/// protection out-of-band when it does not use the built-in <see cref="ValidationOptions.ReplayClaim"/> hook.
	/// </summary>
	public static string? GetSignedRequestNonce(this HttpRequest request) {
		ArgumentNullException.ThrowIfNull(request);
		return TryGetNonce(request.Headers["Signature-Input"].ToString(), request.Headers["Signature"].ToString());
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
