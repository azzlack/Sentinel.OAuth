namespace Sentinel.OAuth.Core.Interfaces.Validators
{
    public interface ITokenValidator
    {
        /// <summary>Validates the authorization code hash.</summary>
        /// <param name="code">The code.</param>
        /// <param name="hash">The hash.</param>
        /// <param name="algorithm">The hashing algorithm.</param>
        /// <returns>true if it succeeds, false if it fails.</returns>
        bool ValidateAuthorizationCodeHash(string code, string hash, string algorithm);

        /// <summary>Validates the access token hash.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <param name="hash">The hash.</param>
        /// <param name="algorithm">The hashing algorithm.</param>
        /// <returns>true if it succeeds, false if it fails.</returns>
        bool ValidateAccessTokenHash(string accessToken, string hash, string algorithm);
    }
}
