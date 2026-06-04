namespace System.Net.Http;

/// <summary>
/// Credentials for signing HTTP requests.
/// </summary>
/// <param name="ClientId">The public client identifier.</param>
/// <param name="SigningSecret">The secret key used for HMAC signature.</param>
public sealed record SigningCredentials(string ClientId, string SigningSecret);
