namespace Sentinel.OAuth.Core.Interfaces.Repositories
{
    using Sentinel.OAuth.Core.Interfaces.Models;
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    /// <summary>Interface for token repository.</summary>
    public interface ITokenRepository
    {
        /// <summary>Gets the specified authorization code.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns>The authorization code.</returns>
        Task<IAuthorizationCode> GetAuthorizationCode(string identifier);

        /// <summary>
        /// Gets all authorization codes that matches the specified redirect uri and expires after the specified date.
        /// Called when authenticating an authorization code.
        /// </summary>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The authorization codes.</returns>
        Task<IEnumerable<IAuthorizationCode>> GetAuthorizationCodes(string redirectUri, DateTimeOffset expires);

        /// <summary>
        /// Inserts the specified authorization code.
        /// Called when creating an authorization code.
        /// </summary>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns>The inserted authorization code. <c>null</c> if the insertion was unsuccessful.</returns>
        Task<IAuthorizationCode> InsertAuthorizationCode(IAuthorizationCode authorizationCode);

        /// <summary>
        /// Deletes the authorization codes that expires before the specified expire date.
        /// Called when creating an authorization code to cleanup.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted codes.</returns>
        Task<int> DeleteAuthorizationCodes(DateTimeOffset expires);

        /// <summary>Deletes the specified authorization code.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        Task<bool> DeleteAuthorizationCode(string identifier);

        /// <summary>Deletes the specified authorization code.</summary>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        Task<bool> DeleteAuthorizationCode(IAuthorizationCode authorizationCode);

        /// <summary>Gets the specified access token.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns>The access token.</returns>
        Task<IAccessToken> GetAccessToken(string identifier);

        /// <summary>
        /// Gets all access tokens that expires **after** the specified date.
        /// Called when authenticating an access token to limit the number of tokens to go through when validating the hash.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The access tokens.</returns>
        Task<IEnumerable<IAccessToken>> GetAccessTokens(DateTimeOffset expires);

        /// <summary>
        /// Gets all access tokens for the specified user that expires **after** the specified date. 
        /// </summary>
        /// <param name="subject">The subject.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The access tokens.</returns>
        Task<IEnumerable<IAccessToken>> GetAccessTokens(string subject, DateTimeOffset expires);

        /// <summary>
        /// Inserts the specified access token.
        /// Called when creating an access token.
        /// </summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The inserted access token. <c>null</c> if the insertion was unsuccessful.</returns>
        Task<IAccessToken> InsertAccessToken(IAccessToken accessToken);

        /// <summary>
        /// Deletes the access tokens that expires before the specified expire date.
        /// Called when creating an access token to cleanup.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted tokens.</returns>
        Task<int> DeleteAccessTokens(DateTimeOffset expires);

        /// <summary>Deletes the access tokens belonging to the specified client, redirect uri and subject.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="subject">The subject.</param>
        /// <returns>The number of deleted tokens.</returns>
        Task<int> DeleteAccessTokens(string clientId, string redirectUri, string subject);

        /// <summary>Deletes the specified access token.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        Task<bool> DeleteAccessToken(string identifier);

        /// <summary>Deletes the specified access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        Task<bool> DeleteAccessToken(IAccessToken accessToken);

        /// <summary>Gets the specified refresh token.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns>The refresh token.</returns>
        Task<IRefreshToken> GetRefreshToken(string identifier);

        /// <summary>
        /// Gets all refresh tokens for the specified client id that expires after the specified date.
        /// Called when authentication a refresh token to limit the number of tokens to go through when
        /// validating the hash.
        /// </summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The refresh tokens.</returns>
        Task<IEnumerable<IRefreshToken>> GetClientRefreshTokens(string clientId, DateTimeOffset expires);

        /// <summary>
        /// Gets all refresh tokens for the specified user that expires **after** the specified date. 
        /// </summary>
        /// <param name="subject">The subject.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The refresh tokens.</returns>
        Task<IEnumerable<IRefreshToken>> GetUserRefreshTokens(string subject, DateTimeOffset expires);

        /// <summary>
        /// Inserts the specified refresh token.
        /// Called when creating a refresh token.
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>The inserted refresh token. <c>null</c> if the insertion was unsuccessful.</returns>
        Task<IRefreshToken> InsertRefreshToken(IRefreshToken refreshToken);

        /// <summary>
        /// Deletes the refresh tokens that expires before the specified expire date.
        /// Called when creating a refresh token to cleanup.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted tokens.</returns>
        Task<int> DeleteRefreshTokens(DateTimeOffset expires);

        /// <summary>Deletes the refresh tokens belonging to the specified client, redirect uri and subject.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="subject">The subject.</param>
        /// <returns>The number of deleted tokens.</returns>
        Task<int> DeleteRefreshTokens(string clientId, string redirectUri, string subject);

        /// <summary>Deletes the specified refresh token.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        Task<bool> DeleteRefreshToken(string identifier);

        /// <summary>Deletes the specified refresh token.</summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        Task<bool> DeleteRefreshToken(IRefreshToken refreshToken);

        /// <summary>Deletes all access tokens, refresh tokens and authorization codes.</summary>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        Task<bool> Purge();
    }
}