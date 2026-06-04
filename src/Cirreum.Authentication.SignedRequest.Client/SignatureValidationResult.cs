namespace System.Net.Http;

/// <summary>
/// Result of validating a signed request signature.
/// </summary>
public readonly struct SignatureValidationResult {

	/// <summary>
	/// Gets whether the validation was successful.
	/// </summary>
	public bool IsValid { get; }

	/// <summary>
	/// Gets the error message if validation failed, or null if successful.
	/// </summary>
	public string? ErrorMessage { get; }

	private SignatureValidationResult(bool isValid, string? errorMessage) {
		this.IsValid = isValid;
		this.ErrorMessage = errorMessage;
	}

	/// <summary>
	/// Creates a successful validation result.
	/// </summary>
	public static SignatureValidationResult Success() => new(true, null);

	/// <summary>
	/// Creates a failed validation result with an error message.
	/// </summary>
	/// <param name="errorMessage">The reason for the failure.</param>
	public static SignatureValidationResult Failed(string errorMessage) => new(false, errorMessage);

	/// <summary>
	/// Throws an exception if validation failed.
	/// </summary>
	/// <exception cref="InvalidOperationException">Thrown when validation failed.</exception>
	public void ThrowIfInvalid() {
		if (!this.IsValid) {
			throw new InvalidOperationException(this.ErrorMessage ?? "Signature validation failed.");
		}
	}
}
