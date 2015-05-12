namespace Sentinel.OAuth.Core.Interfaces.Repositories
{
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Interfaces.Models;

    /// <summary>Interface for token repository.</summary>
    public interface ITokenRepository
    {
        /// <summary>
        /// Gets all authorization codes that matches the specified redirect uri and expires after the specified date.
        /// Called when authenticating an authorization code.
        /// </summary>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The authorization codes.</returns>
        Task<IEnumerable<IAuthorizationCode>> GetAuthorizationCodes(string redirectUri, DateTime expires);

        /// <summary>
        /// Inserts the specified authorization code.
        /// Called when creating an authorization code.
        /// </summary>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns>The inserted authorization code. <c>null</c> if the insertion was unsuccessful.</returns>
        Task<IAuthorizationCode> InsertAuthorizationCode(IAuthorizationCode authorizationCode);

        /// <summary>
        /// Deletes the authorization code that belongs to the specified client, redirect uri and user combination.
        /// Called when creating an authorization code to prevent duplicate authorization codes.
        /// </summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="userId">Identifier for the user.</param>
        /// <returns>The number of deleted codes.</returns>
        Task<bool> DeleteAuthorizationCodes(string clientId, string redirectUri, string userId);

        /// <summary>
        /// Deletes the authorization codes that expires before the specified expire date.
        /// Called when creating an authorization code to cleanup.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted codes.</returns>
        Task<int> DeleteAuthorizationCodes(DateTime expires);

        /// <summary>
        /// Deletes the specified authorization code.
        /// Called when authenticating an authorization code to prevent re-use.
        /// </summary>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        Task<bool> DeleteAuthorizationCode(IAuthorizationCode authorizationCode);

        /// <summary>
        /// Gets all access tokens that expires **after** the specified date.
        /// Called when authenticating an access token to limit the number of tokens to go through when validating the hash.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The access tokens.</returns>
        Task<IEnumerable<IAccessToken>> GetAccessTokens(DateTime expires);

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
        Task<int> DeleteAccessTokens(DateTime expires);

        /// <summary>
        /// Deletes the access token that belongs to the specified client, redirect uri and user combination.
        /// Called when creating an access token to prevent duplicate access tokens.
        /// </summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="userId">Identifier for the user.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        Task<bool> DeleteAccessToken(string clientId, string redirectUri, string userId);

        /// <summary>
        /// Gets all refresh tokens that matches the specified redirect uri and expires after the specified date.
        /// Called when authentication a refresh token to limit the number of tokens to go through when validating the hash.
        /// </summary>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The refresh tokens.</returns>
        Task<IEnumerable<IRefreshToken>> GetRefreshTokens(string redirectUri, DateTime expires);

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
        Task<int> DeleteRefreshTokens(DateTime expires);

        /// <summary>
        /// Deletes the specified refresh token.
        /// Called when authenticating a refresh token to prevent re-use.
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        Task<bool> DeleteRefreshToken(IRefreshToken refreshToken);

        /// <summary>
        /// Deletes the refresh token that belongs to the specified client, redirect uri and user combination.
        /// Called when creating a refresh token to prevent duplicate refresh tokens.
        /// </summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="userId">Identifier for the user.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        Task<bool> DeleteRefreshToken(string clientId, string redirectUri, string userId);
    }
}