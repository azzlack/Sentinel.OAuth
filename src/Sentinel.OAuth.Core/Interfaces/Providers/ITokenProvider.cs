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
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="code">The code.</param>
        /// <returns>The access token if valid, <c>null</c> otherwise.</returns>
        Task<IAuthorizationCode> ValidateAuthorizationCode(string redirectUri, string code);

        /// <summary>Creates an access token.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="expireTime">The expire time.</param>
        /// <returns>An object containing the new access token entity and the hashed token.</returns>
        Task<TokenCreationResult<IAccessToken>> CreateAccessToken(string clientId, string redirectUri, ISentinelPrincipal userPrincipal, IEnumerable<string> scope, DateTimeOffset expireTime);

        /// <summary>Validates an access token.</summary>
        /// <param name="token">The token.</param>
        /// <returns>The access token if valid, <c>null</c> otherwise.</returns>
        Task<IAccessToken> ValidateAccessToken(string token);

        /// <summary>Creates an access token.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="expireTime">The expire time.</param>
        /// <returns>An object containing the new access token entity and the hashed token.</returns>
        Task<TokenCreationResult<IRefreshToken>> CreateRefreshToken(string clientId, string redirectUri, ISentinelPrincipal userPrincipal, IEnumerable<string> scope, DateTimeOffset expireTime);

        /// <summary>Validates an access token.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="token">The token.</param>
        /// <returns>The access token if valid, <c>null</c> otherwise.</returns>
        Task<IRefreshToken> ValidateRefreshToken(string clientId, string redirectUri, string token);
    }
}