namespace Sentinel.OAuth.Core.Interfaces.Repositories
{
    using System;
    using System.Collections.Generic;
    using System.Linq.Expressions;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Interfaces.Models;

    /// <summary>Interface for token repository.</summary>
    /// <typeparam name="TAccessToken">The access token type.</typeparam>
    /// <typeparam name="TRefreshToken">The refresh token type.</typeparam>
    /// <typeparam name="TAuthorizationCode">The authorization code type.</typeparam>
    public interface ITokenRepository<TAccessToken, TRefreshToken, TAuthorizationCode>
        where TAccessToken : IAccessToken
        where TRefreshToken : IRefreshToken
        where TAuthorizationCode : IAuthorizationCode
    {
        /// <summary>Gets authorization codes matching the specified predicate.</summary>
        /// <param name="predicate">The predicate expression for reducing the authorization code collection.</param>
        /// <returns>The authorization codes.</returns>
        Task<IEnumerable<TAuthorizationCode>> GetAuthorizationCodes(Expression<Func<TAuthorizationCode, bool>> predicate);

        /// <summary>Inserts the specified authorization code.</summary>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns>The inserted authorization code. <c>null</c> if the insertion was unsuccessful.</returns>
        Task<TAuthorizationCode> InsertAuthorizationCode(TAuthorizationCode authorizationCode);

        /// <summary>Deletes the specified authorization code.</summary>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        Task<bool> DeleteAuthorizationCode(TAuthorizationCode authorizationCode);

        /// <summary>Gets access tokens matching the specified predicate.</summary>
        /// <param name="predicate">The predicate expression for reducing the access token collection.</param>
        /// <returns>The access tokens.</returns>
        Task<IEnumerable<TAccessToken>> GetAccessTokens(Expression<Func<TAccessToken, bool>> predicate);

        /// <summary>Inserts the specified access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The inserted access token. <c>null</c> if the insertion was unsuccessful.</returns>
        Task<TAccessToken> InsertAccessToken(TAccessToken accessToken);

        /// <summary>Deletes the specified access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        Task<bool> DeleteAccessToken(TAccessToken accessToken);

        /// <summary>Gets refresh tokens matching the specified predicate.</summary>
        /// <param name="predicate">The predicate expression for reducing the refresh token collection.</param>
        /// <returns>The refresh tokens.</returns>
        Task<IEnumerable<TRefreshToken>> GetRefreshTokens(Expression<Func<TRefreshToken, bool>> predicate);

        /// <summary>Inserts the specified refresh token.</summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>The inserted refresh token. <c>null</c> if the insertion was unsuccessful.</returns>
        Task<TRefreshToken> InsertRefreshToken(TRefreshToken refreshToken);

        /// <summary>Deletes the specified refresh token.</summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        Task<bool> DeleteRefreshToken(TRefreshToken refreshToken);
    }
}