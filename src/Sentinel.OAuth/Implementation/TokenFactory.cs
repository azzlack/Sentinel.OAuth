namespace Sentinel.OAuth.Implementation
{
    using System;

    using Sentinel.OAuth.Core.Interfaces.Factories;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models.OAuth;

    /// <summary>A token factory.</summary>
    public class TokenFactory : ITokenFactory
    {
        /// <summary>Creates an access token.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">URI of the redirect.</param>
        /// <param name="userId">Identifier for the user.</param>
        /// <param name="token">The token.</param>
        /// <param name="ticket">The ticket.</param>
        /// <param name="validTo">The valid to Date/Time.</param>
        /// <returns>The new access token.</returns>
        public IAccessToken CreateAccessToken(string clientId, string redirectUri, string userId, string token, string ticket, DateTime validTo)
        {
            return new AccessToken
                       {
                           Token = token,
                           ValidTo = validTo,
                           ClientId = clientId,
                           Subject = userId,
                           Ticket = ticket,
                           RedirectUri = redirectUri
                       };
        }

        /// <summary>Creates a refresh token.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">URI of the redirect.</param>
        /// <param name="userId">Identifier for the user.</param>
        /// <param name="token">The token.</param>
        /// <param name="validTo">The valid to Date/Time.</param>
        /// <returns>The new refresh token.</returns>
        public IRefreshToken CreateRefreshToken(string clientId, string redirectUri, string userId, string token, DateTime validTo)
        {
            return new RefreshToken()
                       {
                           ClientId = clientId,
                           RedirectUri = redirectUri,
                           Subject = userId,
                           Token = token,
                           ValidTo = validTo
                       };
        }

        /// <summary>Creates an authorization code.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">URI of the redirect.</param>
        /// <param name="userId">Identifier for the user.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="code">The code.</param>
        /// <param name="ticket">The ticket.</param>
        /// <param name="validTo">The valid to Date/Time.</param>
        /// <returns>The new authorization code.</returns>
        public IAuthorizationCode CreateAuthorizationCode(string clientId, string redirectUri, string userId, string[] scope, string code, string ticket, DateTime validTo)
        {
            return new AuthorizationCode()
                       {
                           ClientId = clientId,
                           RedirectUri = redirectUri,
                           Subject = userId,
                           Code = code,
                           Ticket = ticket,
                           Scope = scope,
                           ValidTo = validTo
                       };
        }
    }
}