namespace System.Net.Http;

/// <summary>
/// Credentials for signing HTTP requests.
/// </summary>
/// <param name="KeyId">The credential identifier (the RFC 9421 <c>keyid</c>) the verifier resolves the secret by.</param>
/// <param name="SigningSecret">The shared secret used for the HMAC signature.</param>
public sealed record SigningCredentials(string KeyId, string SigningSecret) {

	/// <summary>
	/// Redacts the secret from the synthesized record string, so a credential cannot leak it through logging
	/// or string interpolation.
	/// </summary>
	public override string ToString() => $"{nameof(SigningCredentials)} {{ KeyId = {this.KeyId}, SigningSecret = [redacted] }}";
}
