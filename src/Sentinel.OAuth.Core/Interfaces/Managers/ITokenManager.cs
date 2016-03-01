namespace Sentinel.OAuth.Core.Interfaces.Managers
{
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models;

    /// <summary>Interface for token validation and creation.</summary>
    public interface ITokenManager
    {
        /// <summary>
        /// Authenticates the authorization code.
        /// </summary>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns>The user principal.</returns>
        Task<ISentinelPrincipal> AuthenticateAuthorizationCodeAsync(string redirectUri, string authorizationCode);

        /// <summary>Authenticates the access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The user principal.</returns>
        Task<ISentinelPrincipal> AuthenticateAccessTokenAsync(string accessToken);

        /// <summary>
        /// Authenticates the refresh token.
        /// </summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>The user principal.</returns>
        Task<ISentinelPrincipal> AuthenticateRefreshTokenAsync(string clientId, string refreshToken);

        /// <summary>
        /// Generates an authorization code for the specified client.
        /// </summary>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="expire">The expire time.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="scope">The scope.</param>
        /// <returns>The token creation result.</returns>
        Task<TokenCreationResult<IAuthorizationCode>> CreateAuthorizationCodeAsync(ISentinelPrincipal userPrincipal, TimeSpan expire, string redirectUri, IEnumerable<string> scope);

        /// <summary>Creates an access token.</summary>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="expire">The expire time.</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="scope">The scope.</param>
        /// <returns>The token creation result.</returns>
        Task<TokenCreationResult<IAccessToken>> CreateAccessTokenAsync(ISentinelPrincipal userPrincipal, TimeSpan expire, string clientId, string redirectUri, IEnumerable<string> scope);

        /// <summary>Creates a refresh token.</summary>
        /// <param name="userPrincipal">The principal.</param>
        /// <param name="expire">The expire time.</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="scope">The scope.</param>
        /// <returns>The token creation result.</returns>
        Task<TokenCreationResult<IRefreshToken>> CreateRefreshTokenAsync(ISentinelPrincipal userPrincipal, TimeSpan expire, string clientId, string redirectUri, IEnumerable<string> scope);
    }
}