namespace Sentinel.OAuth.Core.Interfaces.Providers
{
    using Identity;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models;
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    public interface ITokenProvider
    {
        /// <summary>Creates an authorization code.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="expireTime">The expire time.</param>
        /// <returns>An object containing the new access token entity and the hashed token.</returns>
        Task<TokenCreationResult<IAuthorizationCode>> CreateAuthorizationCode(string clientId, string redirectUri, ISentinelPrincipal userPrincipal, IEnumerable<string> scope, DateTimeOffset expireTime);

        /// <summary>Validates an authorization code.</summary>
        /// <param name="authorizationCodes">The authorization codes to validate against.</param>
        /// <param name="code">The code.</param>
        /// <returns>The token principal if valid, <c>null</c> otherwise.</returns>
        Task<TokenValidationResult<IAuthorizationCode>> ValidateAuthorizationCode(IEnumerable<IAuthorizationCode> authorizationCodes, string code);

        /// <summary>Creates an access token.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="expireTime">The expire time.</param>
        /// <returns>An object containing the new access token entity and the hashed token.</returns>
        Task<TokenCreationResult<IAccessToken>> CreateAccessToken(string clientId, string redirectUri, ISentinelPrincipal userPrincipal, IEnumerable<string> scope, DateTimeOffset expireTime);

        /// <summary>Validates the access token.</summary>
        /// <param name="accessTokens">The access tokens to validate against.</param>
        /// <param name="token">The token.</param>
        /// <returns>The token principal if valid, <c>null</c> otherwise.</returns>
        Task<TokenValidationResult<IAccessToken>> ValidateAccessToken(IEnumerable<IAccessToken> accessTokens, string token);

        /// <summary>Creates a refresh token.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="expireTime">The expire time.</param>
        /// <returns>An object containing the new access token entity and the hashed token.</returns>
        Task<TokenCreationResult<IRefreshToken>> CreateRefreshToken(string clientId, string redirectUri, ISentinelPrincipal userPrincipal, IEnumerable<string> scope, DateTimeOffset expireTime);

        /// <summary>Validates the refresh token.</summary>
        /// <param name="refreshTokens">The refresh tokens to validate against.</param>
        /// <param name="token">The token.</param>
        /// <returns>The token principal if valid, <c>null</c> otherwise.</returns>
        Task<TokenValidationResult<IRefreshToken>> ValidateRefreshToken(IEnumerable<IRefreshToken> refreshTokens, string token);
    }
}