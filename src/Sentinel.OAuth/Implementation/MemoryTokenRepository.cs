namespace Sentinel.OAuth.Implementation
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Linq;
    using System.Linq.Expressions;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Models.OAuth;

    public class MemoryTokenRepository : ITokenRepository<AccessToken, RefreshToken, AuthorizationCode>
    {
        /// <summary>The authorization codes.</summary>
        private readonly ConcurrentDictionary<long, AuthorizationCode> authorizationCodes;

        /// <summary>The refresh tokens.</summary>
        private readonly ConcurrentDictionary<long, RefreshToken> refreshTokens;

        /// <summary>The access tokens.</summary>
        private readonly ConcurrentDictionary<long, AccessToken> accessTokens;

        /// <summary>
        /// Initializes a new instance of the Sentinel.OAuth.Implementation.MemoryTokenRepository class.
        /// </summary>
        public MemoryTokenRepository()
        {
            this.authorizationCodes = new ConcurrentDictionary<long, AuthorizationCode>();
            this.refreshTokens = new ConcurrentDictionary<long, RefreshToken>();
            this.accessTokens = new ConcurrentDictionary<long, AccessToken>();
        }

        /// <summary>
        /// Gets authorization codes with the specified redirect uri and has an expiry date later than
        /// the specified datetime.
        /// </summary>
        /// <param name="predicate">
        /// The predicate expression for reducing the authorization code collection.
        /// </param>
        /// <returns>The authorization codes.</returns>
        public async Task<IEnumerable<AuthorizationCode>> GetAuthorizationCodes(Expression<Func<AuthorizationCode, bool>> predicate)
        {
            return this.authorizationCodes.Select(x => x.Value).Where(predicate.Compile());
        }

        /// <summary>Inserts the specified authorization code.</summary>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns>The inserted authorization code. <c>null</c> if the insertion was unsuccessful.</returns>
        public async Task<AuthorizationCode> InsertAuthorizationCode(AuthorizationCode authorizationCode)
        {
            // Autogenerate id 
            authorizationCode.Id = this.authorizationCodes.Any() ? this.authorizationCodes.Max(x => x.Key) + 1 : 1;

            if (this.authorizationCodes.TryAdd(authorizationCode.Id, authorizationCode))
            {
                return authorizationCode;
            }

            return null;
        }

        /// <summary>Deletes the authorization code with the specified id.</summary>
        /// <exception cref="ArgumentException">
        ///     Thrown when one or more arguments have unsupported or illegal values.
        /// </exception>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAuthorizationCode(AuthorizationCode authorizationCode)
        {
            if (authorizationCode == null || authorizationCode.Id <= 0)
            {
                throw new ArgumentException("The supplied authorization code is invalid.");
            }

            if (!this.authorizationCodes.ContainsKey(authorizationCode.Id))
            {
                throw new ArgumentException(string.Format("No authorization code with id '{0}' exist", authorizationCode.Id));
            }

            AuthorizationCode removedCode;
            if (this.authorizationCodes.TryRemove(authorizationCode.Id, out removedCode))
            {
                return true;
            }

            return false;
        }

        /// <summary>Gets access tokens matching the specified predicate.</summary>
        /// <param name="predicate">
        ///     The predicate expression for reducing the access token collection.
        /// </param>
        /// <returns>The access tokens.</returns>
        public async Task<IEnumerable<AccessToken>> GetAccessTokens(Expression<Func<AccessToken, bool>> predicate)
        {
            return this.accessTokens.Select(x => x.Value).Where(predicate.Compile());
        }

        /// <summary>Inserts the specified access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The inserted access token. <c>null</c> if the insertion was unsuccessful.</returns>
        public async Task<AccessToken> InsertAccessToken(AccessToken accessToken)
        {
            // Autogenerate id 
            accessToken.Id = this.accessTokens.Any() ? this.accessTokens.Max(x => x.Key) + 1 : 1;

            if (this.accessTokens.TryAdd(accessToken.Id, accessToken))
            {
                return accessToken;
            }

            return null;
        }

        /// <summary>Deletes the access token with the specified id.</summary>
        /// <exception cref="ArgumentException">
        ///     Thrown when one or more arguments have unsupported or illegal values.
        /// </exception>
        /// <param name="accessToken">The access token.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAccessToken(AccessToken accessToken)
        {
            if (accessToken == null || accessToken.Id <= 0)
            {
                throw new ArgumentException("The supplied authorization code is invalid.");
            }

            if (!this.accessTokens.ContainsKey(accessToken.Id))
            {
                throw new ArgumentException(string.Format("No access token with id '{0}' exist", accessToken.Id));
            }

            AccessToken removedToken;
            if (this.accessTokens.TryRemove(accessToken.Id, out removedToken))
            {
                return true;
            }

            return false;
        }

        /// <summary>Gets refresh tokens matching the specified predicate.</summary>
        /// <param name="predicate">
        ///     The predicate expression for reducing the refresh token collection.
        /// </param>
        /// <returns>The refresh tokens.</returns>
        public async Task<IEnumerable<RefreshToken>> GetRefreshTokens(Expression<Func<RefreshToken, bool>> predicate)
        {
            return this.refreshTokens.Select(x => x.Value).Where(predicate.Compile());
        }

        /// <summary>Inserts the specified refresh token.</summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>
        ///     The inserted refresh token. <c>null</c> if the insertion was unsuccessful.
        /// </returns>
        public async Task<RefreshToken> InsertRefreshToken(RefreshToken refreshToken)
        {
            // Autogenerate id 
            refreshToken.Id = this.refreshTokens.Any() ? this.refreshTokens.Max(x => x.Key) + 1 : 1;

            if (this.refreshTokens.TryAdd(refreshToken.Id, refreshToken))
            {
                return refreshToken;
            }

            return null;
        }

        /// <summary>Deletes the refresh token with the specified id.</summary>
        /// <exception cref="ArgumentException">
        ///     Thrown when one or more arguments have unsupported or illegal values.
        /// </exception>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteRefreshToken(RefreshToken refreshToken)
        {
            if (refreshToken == null || refreshToken.Id <= 0)
            {
                throw new ArgumentException("The supplied authorization code is invalid.");
            }

            if (!this.refreshTokens.ContainsKey(refreshToken.Id))
            {
                throw new ArgumentException(string.Format("No refresh token with id '{0}' exist", refreshToken.Id));
            }

            RefreshToken removedToken;
            if (this.refreshTokens.TryRemove(refreshToken.Id, out removedToken))
            {
                return true;
            }

            return false;
        }
    }
}