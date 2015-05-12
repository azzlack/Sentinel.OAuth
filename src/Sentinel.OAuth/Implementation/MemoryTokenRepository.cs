namespace Sentinel.OAuth.Implementation
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Linq;
    using System.Linq.Expressions;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Models.OAuth;

    public class MemoryTokenRepository : ITokenRepository
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
        /// Gets all authorization codes that matches the specified redirect uri and expires after the
        /// specified date.
        /// </summary>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The authorization codes.</returns>
        public async Task<IEnumerable<IAuthorizationCode>> GetAuthorizationCodes(string redirectUri, DateTime expires)
        {
            return this.authorizationCodes.Where(x => x.Value.RedirectUri == redirectUri && x.Value.ValidTo > expires).Select(x => x.Value);
        }

        /// <summary>
        /// Gets all authorization codes that matches the specified client redirect uri and user
        /// combination.
        /// </summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="userId">Identifier for the user.</param>
        /// <returns>The authorization codes.</returns>
        public async Task<IEnumerable<IAuthorizationCode>> GetAuthorizationCodes(string clientId, string redirectUri, string userId)
        {
            return this.authorizationCodes.Where(x => x.Value.ClientId == clientId && x.Value.RedirectUri == redirectUri && x.Value.Subject == userId).Select(x => x.Value);
        }

        /// <summary>Inserts the specified authorization code.</summary>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns>The inserted authorization code. <c>null</c> if the insertion was unsuccessful.</returns>
        public async Task<IAuthorizationCode> InsertAuthorizationCode(IAuthorizationCode authorizationCode)
        {
            var code = (AuthorizationCode)authorizationCode;
            
            // Autogenerate id 
            code.Id = this.authorizationCodes.Any() ? this.authorizationCodes.Max(x => x.Key) + 1 : 1;

            if (this.authorizationCodes.TryAdd(code.Id, code))
            {
                return authorizationCode;
            }

            return null;
        }

        /// <summary>
        /// Deletes the authorization code that belongs to the specified client, redirect uri and user
        /// combination.
        /// </summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="userId">Identifier for the user.</param>
        /// <returns>The number of deleted codes.</returns>
        public async Task<bool> DeleteAuthorizationCodes(string clientId, string redirectUri, string userId)
        {
            var i = 0;
            var tokens = this.authorizationCodes.Where(x => x.Value.ClientId == clientId && x.Value.RedirectUri == redirectUri && x.Value.Subject == userId).ToList();

            foreach (var token in tokens)
            {
                AuthorizationCode removedCode;
                if (this.authorizationCodes.TryRemove(token.Key, out removedCode))
                {
                    i++;
                }
            }

            return i == 1;
        }

        /// <summary>
        /// Deletes the authorization codes that expires before the specified expire date.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted codes.</returns>
        public async Task<int> DeleteAuthorizationCodes(DateTime expires)
        {
            var i = 0;
            var tokens = this.authorizationCodes.Where(x => x.Value.ValidTo < expires).ToList();

            foreach (var token in tokens)
            {
                AuthorizationCode removedCode;
                if (this.authorizationCodes.TryRemove(token.Key, out removedCode))
                {
                    i++;
                }
            }

            return i;
        }

        /// <summary>Deletes the specified authorization code.</summary>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAuthorizationCode(IAuthorizationCode authorizationCode)
        {
            var exists = this.authorizationCodes.Any(x => x.Value.Equals(authorizationCode));

            if (exists)
            {
                var code = this.authorizationCodes.First(x => x.Value.Equals(authorizationCode));

                AuthorizationCode removedCode;
                return this.authorizationCodes.TryRemove(code.Key, out removedCode);
            }

            return false;
        }

        /// <summary>Gets all access tokens that expires after the specified date.</summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The access tokens.</returns>
        public async Task<IEnumerable<IAccessToken>> GetAccessTokens(DateTime expires)
        {
            return this.accessTokens.Select(x => x.Value).Where(x => x.ValidTo > expires);
        }

        /// <summary>Gets access tokens matching the specified predicate.</summary>
        /// <param name="predicate">
        ///     The predicate expression for reducing the access token collection.
        /// </param>
        /// <returns>The access tokens.</returns>
        public async Task<IEnumerable<IAccessToken>> GetAccessTokens(Expression<Func<IAccessToken, bool>> predicate)
        {
            return this.accessTokens.Select(x => x.Value).Where(predicate.Compile());
        }

        /// <summary>Inserts the specified access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The inserted access token. <c>null</c> if the insertion was unsuccessful.</returns>
        public async Task<IAccessToken> InsertAccessToken(IAccessToken accessToken)
        {
            var token = (AccessToken)accessToken;

            // Autogenerate id 
            token.Id = this.accessTokens.Any() ? this.accessTokens.Max(x => x.Key) + 1 : 1;

            if (this.accessTokens.TryAdd(token.Id, token))
            {
                return accessToken;
            }

            return null;
        }

        /// <summary>
        /// Deletes the access token that belongs to the specified client, redirect uri and user
        /// combination.
        /// </summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="userId">Identifier for the user.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAccessToken(string clientId, string redirectUri, string userId)
        {
            var i = 0;
            var tokens = this.accessTokens.Where(x => x.Value.ClientId == clientId && x.Value.RedirectUri == redirectUri && x.Value.Subject == userId).ToList();

            foreach (var token in tokens)
            {
                AccessToken removedToken;
                if (this.accessTokens.TryRemove(token.Key, out removedToken))
                {
                    i++;
                }
            }

            return i == 1;
        }

        /// <summary>
        /// Deletes the access tokens that expires before the specified expire date. combination.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<int> DeleteAccessTokens(DateTime expires)
        {
            var i = 0;
            var tokens = this.accessTokens.Where(x => x.Value.ValidTo < expires).ToList();

            foreach (var token in tokens)
            {
                AccessToken removedToken;
                if (this.accessTokens.TryRemove(token.Key, out removedToken))
                {
                    i++;
                }
            }

            return i;
        }

        /// <summary>
        /// Gets all refresh tokens that matches the specified redirect uri and expires after the
        /// specified date.
        /// </summary>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The refresh tokens.</returns>
        public async Task<IEnumerable<IRefreshToken>> GetRefreshTokens(string redirectUri, DateTime expires)
        {
            return this.refreshTokens.Select(x => x.Value).Where(x => x.RedirectUri == redirectUri && x.ValidTo > expires);
        }

        /// <summary>Inserts the specified refresh token.</summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>
        ///     The inserted refresh token. <c>null</c> if the insertion was unsuccessful.
        /// </returns>
        public async Task<IRefreshToken> InsertRefreshToken(IRefreshToken refreshToken)
        {
            var token = (RefreshToken)refreshToken;

            // Autogenerate id 
            token.Id = this.refreshTokens.Any() ? this.refreshTokens.Max(x => x.Key) + 1 : 1;

            if (this.refreshTokens.TryAdd(token.Id, token))
            {
                return refreshToken;
            }

            return null;
        }

        /// <summary>
        /// Deletes the refresh token that belongs to the specified client, redirect uri and user
        /// combination.
        /// </summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="userId">Identifier for the user.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<bool> DeleteRefreshToken(string clientId, string redirectUri, string userId)
        {
            var i = 0;
            var tokens = this.refreshTokens.Where(x => x.Value.ClientId == clientId && x.Value.RedirectUri == redirectUri && x.Value.Subject == userId).ToList();

            foreach (var token in tokens)
            {
                RefreshToken removedToken;
                if (this.refreshTokens.TryRemove(token.Key, out removedToken))
                {
                    i++;
                }
            }

            return i == 1;
        }

        /// <summary>
        /// Deletes the refresh tokens that expires before the specified expire date. combination.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<int> DeleteRefreshTokens(DateTime expires)
        {
            var i = 0;
            var tokens = this.refreshTokens.Where(x => x.Value.ValidTo < expires).ToList();

            foreach (var token in tokens)
            {
                RefreshToken removedToken;
                if (this.refreshTokens.TryRemove(token.Key, out removedToken))
                {
                    i++;
                }
            }

            return i;
        }

        /// <summary>Deletes the specified refresh token.</summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteRefreshToken(IRefreshToken refreshToken)
        {
            var exists = this.refreshTokens.Any(x => x.Value.Equals(refreshToken));

            if (exists)
            {
                var token = this.refreshTokens.First(x => x.Value.Equals(refreshToken));

                RefreshToken removedToken;
                return this.refreshTokens.TryRemove(token.Key, out removedToken);
            }

            return false;
        }
    }
}