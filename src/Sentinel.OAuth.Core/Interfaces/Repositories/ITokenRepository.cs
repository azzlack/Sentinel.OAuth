namespace Sentinel.OAuth.Core.Interfaces.Repositories
{
    using System;
    using System.Collections.Generic;
    using System.Linq.Expressions;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Models.OAuth;

    /// <summary>Interface for token repository.</summary>
    public interface ITokenRepository
    {
        /// <summary>Gets authorization codes matching the specified predicate.</summary>
        /// <param name="predicate">The predicate expression for reducing the authorization code collection.</param>
        /// <returns>The authorization codes.</returns>
        Task<IEnumerable<AuthorizationCode>> GetAuthorizationCodes(Expression<Func<AuthorizationCode, bool>> predicate);

        /// <summary>Inserts the specified authorization code.</summary>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns>The inserted authorization code. <c>null</c> if the insertion was unsuccessfull.</returns>
        Task<AuthorizationCode> InsertAuthorizationCode(AuthorizationCode authorizationCode);

        /// <summary>Deletes the specified authorization code.</summary>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns><c>True</c> if successfull, <c>false</c> otherwise.</returns>
        Task<bool> DeleteAuthorizationCode(AuthorizationCode authorizationCode);

        /// <summary>Gets access tokens matching the specified predicate.</summary>
        /// <param name="predicate">The predicate expression for reducing the access token collection.</param>
        /// <returns>The access tokens.</returns>
        Task<IEnumerable<AccessToken>> GetAccessTokens(Expression<Func<AccessToken, bool>> predicate);

        /// <summary>Inserts the specified access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The inserted access token. <c>null</c> if the insertion was unsuccessfull.</returns>
        Task<AccessToken> InsertAccessToken(AccessToken accessToken);

        /// <summary>Deletes the specified access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns><c>True</c> if successfull, <c>false</c> otherwise.</returns>
        Task<bool> DeleteAccessToken(AccessToken accessToken);

        /// <summary>Gets refresh tokens matching the specified predicate.</summary>
        /// <param name="predicate">The predicate expression for reducing the refresh token collection.</param>
        /// <returns>The refresh tokens.</returns>
        Task<IEnumerable<RefreshToken>> GetRefreshTokens(Expression<Func<RefreshToken, bool>> predicate);

        /// <summary>Inserts the specified refresh token.</summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>The inserted refresh token. <c>null</c> if the insertion was unsuccessfull.</returns>
        Task<RefreshToken> InsertRefreshToken(RefreshToken refreshToken);

        /// <summary>Deletes the specified refresh token.</summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns><c>True</c> if successfull, <c>false</c> otherwise.</returns>
        Task<bool> DeleteRefreshToken(RefreshToken refreshToken);
    }
}