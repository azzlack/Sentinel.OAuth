namespace Sentinel.OAuth.Core.Interfaces.Managers
{
    using System;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Interfaces.Repositories;

    /// <summary>Interface for token validation and creation.</summary>
    public interface ITokenManager
    {
        /// <summary>The token repository.</summary>
        /// <value>The token repository.</value>
        ITokenRepository TokenRepository { get; }

        /// <summary>
        /// Authenticates the authorization code.
        /// </summary>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns>The user principal.</returns>
        Task<ClaimsPrincipal> AuthenticateAuthorizationCodeAsync(string redirectUri, string authorizationCode);

        /// <summary>Authenticates the access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The user principal.</returns>
        Task<ClaimsPrincipal> AuthenticateAccessTokenAsync(string accessToken);

        /// <summary>
        /// Authenticates the refresh token.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="refreshToken">The refresh token.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <returns>The user principal.</returns>
        Task<ClaimsPrincipal> AuthenticateRefreshTokenAsync(string clientId, string refreshToken, string redirectUri);

        /// <summary>
        /// Generates an authorization code for the specified client.
        /// </summary>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="expire">The expire time.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="scope">The scope.</param>
        /// <returns>An authorization code.</returns>
        Task<string> CreateAuthorizationCodeAsync(ClaimsPrincipal userPrincipal, TimeSpan expire, string redirectUri, string[] scope = null);

        /// <summary>Creates an access token.</summary>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="expire">The expire time.</param>
        /// <param name="clientId">.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <returns>An access token.</returns>
        Task<string> CreateAccessTokenAsync(ClaimsPrincipal userPrincipal, TimeSpan expire, string clientId, string redirectUri);

        /// <summary>
        /// Creates a refresh token.
        /// </summary>
        /// <param name="userPrincipal">The principal.</param>
        /// <param name="expire">The expire time.</param>
        /// <param name="clientId"></param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <returns>A refresh token.</returns>
        Task<string> CreateRefreshTokenAsync(ClaimsPrincipal userPrincipal, TimeSpan expire, string clientId, string redirectUri);
    }
}