namespace Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Implementation
{
    using System;

    using Sentinel.OAuth.Core.Interfaces.Factories;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.TokenManagers.SqlServerTokenRepository.Models.OAuth;

    /// <summary>A token factory for SQL entities.</summary>
    public class SqlTokenFactory : ITokenFactory
    {
        /// <summary>Creates an access token.</summary>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="userId">The user identifier.</param>
        /// <param name="token">The hashed token.</param>
        /// <param name="ticket">The encrypted principal.</param>
        /// <param name="validTo">The point in time where the token expires.</param>
        /// <returns>The new access token.</returns>
        public IAccessToken CreateAccessToken(
            string clientId,
            string redirectUri,
            string userId,
            string token,
            string ticket,
            DateTime validTo)
        {
            return new SqlAccessToken()
                       {
                           ClientId = clientId,
                           RedirectUri = redirectUri,
                           Subject = userId,
                           Token = token,
                           Ticket = ticket,
                           ValidTo = validTo,
                           Created = DateTime.UtcNow
                       };
        }

        /// <summary>Creates a refresh token.</summary>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="userId">The user identifier.</param>
        /// <param name="token">The hashed token.</param>
        /// <param name="validTo">The point in time where the token expires.</param>
        /// <returns>The new refresh token.</returns>
        public IRefreshToken CreateRefreshToken(string clientId, string redirectUri, string userId, string token, DateTime validTo)
        {
            return new SqlRefreshToken()
            {
                ClientId = clientId,
                RedirectUri = redirectUri,
                Subject = userId,
                Token = token,
                ValidTo = validTo,
                Created = DateTime.UtcNow
            };
        }

        /// <summary>Creates an authorization code.</summary>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="userId">The user identifier.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="code">The hashed code.</param>
        /// <param name="ticket">The encrypted principal.</param>
        /// <param name="validTo">The point in time where the code expires.</param>
        /// <returns>The new authorization code.</returns>
        public IAuthorizationCode CreateAuthorizationCode(
            string clientId,
            string redirectUri,
            string userId,
            string[] scope,
            string code,
            string ticket,
            DateTime validTo)
        {
            return new SqlAuthorizationCode()
                       {
                           ClientId = clientId,
                           RedirectUri = redirectUri,
                           Subject = userId,
                           Code = code,
                           Ticket = ticket,
                           Scope = scope,
                           ValidTo = validTo,
                           Created = DateTime.UtcNow
                       };
        }
    }
}