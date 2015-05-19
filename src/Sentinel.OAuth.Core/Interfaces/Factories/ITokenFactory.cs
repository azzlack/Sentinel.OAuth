namespace Sentinel.OAuth.Core.Interfaces.Factories
{
    using System;

    using Sentinel.OAuth.Core.Interfaces.Models;

    /// <summary>Interface for a factory responsible for creating token objects.</summary>
    public interface ITokenFactory
    {
        /// <summary>Creates an access token.</summary>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="userId">The user identifier.</param>
        /// <param name="token">The hashed token.</param>
        /// <param name="ticket">The encrypted principal.</param>
        /// <param name="validTo">The point in time where the token expires.</param>
        /// <returns>The new access token.</returns>
        IAccessToken CreateAccessToken(string clientId, string redirectUri, string userId, string token, string ticket, DateTime validTo);

        /// <summary>Creates a refresh token.</summary>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="userId">The user identifier.</param>
        /// <param name="token">The hashed token.</param>
        /// <param name="validTo">The point in time where the token expires.</param>
        /// <returns>The new refresh token.</returns>
        IRefreshToken CreateRefreshToken(string clientId, string redirectUri, string userId, string token, DateTime validTo);

        /// <summary>Creates an authorization code.</summary>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="userId">The user identifier.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="code">The hashed code.</param>
        /// <param name="ticket">The encrypted principal.</param>
        /// <param name="validTo">The point in time where the code expires.</param>
        /// <returns>The new authorization code.</returns>
        IAuthorizationCode CreateAuthorizationCode(string clientId, string redirectUri, string userId, string[] scope, string code, string ticket, DateTime validTo);
    }
}