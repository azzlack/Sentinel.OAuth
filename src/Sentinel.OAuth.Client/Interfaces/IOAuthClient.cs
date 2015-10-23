namespace Sentinel.OAuth.Client.Interfaces
{
    using Sentinel.OAuth.Core.Models.OAuth.Http;
    using System.Net;
    using System.Threading.Tasks;

    /// <summary>Interface for OAuth clients.</summary>
    public interface IOAuthClient
    {

        /// <summary>
        /// Authenticates the current client and returns an access token.
        /// </summary>
        /// <returns>The access token.</returns>
        Task<AccessTokenResponse> Authenticate();

        /// <summary>
        /// Authenticates the specified user and client and returns an access token.
        /// </summary>
        /// <param name="userName">The username.</param>
        /// <param name="password">The password.</param>
        /// <returns>The access token.</returns>
        Task<AccessTokenResponse> Authenticate(string userName, string password);

        /// <summary>
        /// Re-authenticates by refreshing the access token.
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>The access token.</returns>
        Task<AccessTokenResponse> RefreshAuthentication(string refreshToken);

        /// <summary>Gets the identity.</summary>
        /// <param name="token">The token.</param>
        /// <returns>The identity.</returns>
        Task<IdentityResponse> GetIdentity(string token);

        /// <summary>
        /// Gets the cookies.
        /// </summary>
        /// <returns>A list of cookies.</returns>
        Task<CookieCollection> GetCookies();
    }
}