namespace Sentinel.OAuth.Core.Interfaces.Managers
{
    using System;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Repositories;

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
        /// <param name="redirectUri">The redirect URI.</param>
        /// <returns>The user principal.</returns>
        Task<ISentinelPrincipal> AuthenticateRefreshTokenAsync(string clientId, string refreshToken, string redirectUri);

        /// <summary>
        /// Generates an authorization code for the specified client.
        /// </summary>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="expire">The expire time.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="scope">The scope.</param>
        /// <returns>An authorization code.</returns>
        Task<string> CreateAuthorizationCodeAsync(ISentinelPrincipal userPrincipal, TimeSpan expire, string redirectUri, string[] scope = null);

        /// <summary>Creates an access token.</summary>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="expire">The expire time.</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <returns>An access token.</returns>
        Task<string> CreateAccessTokenAsync(ISentinelPrincipal userPrincipal, TimeSpan expire, string clientId, string redirectUri);

        /// <summary>
        /// Creates a refresh token.
        /// </summary>
        /// <param name="userPrincipal">The principal.</param>
        /// <param name="expire">The expire time.</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <returns>A refresh token.</returns>
        Task<string> CreateRefreshTokenAsync(ISentinelPrincipal userPrincipal, TimeSpan expire, string clientId, string redirectUri);
    }

    /// <summary>Interface for token validation and creation.</summary>
    /// <typeparam name="TAccessToken">The access token type.</typeparam>
    /// <typeparam name="TRefreshToken">The refresh token type.</typeparam>
    /// <typeparam name="TAuthorizationCode">The authorization code type.</typeparam>
    public interface ITokenManager<TAccessToken, TRefreshToken, TAuthorizationCode> : ITokenManager
        where TAccessToken : IAccessToken
        where TRefreshToken : IRefreshToken
        where TAuthorizationCode : IAuthorizationCode
    {
        /// <summary>Gets the token repository.</summary>
        /// <value>The token repository.</value>
        ITokenRepository<TAccessToken, TRefreshToken, TAuthorizationCode> TokenRepository { get; }
    }
}