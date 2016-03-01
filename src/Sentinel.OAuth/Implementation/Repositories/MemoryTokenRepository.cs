namespace Sentinel.OAuth.Implementation.Repositories
{
    using Newtonsoft.Json;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Core.Models.OAuth;
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;

    public class MemoryTokenRepository : ITokenRepository
    {
        /// <summary>The authorization codes.</summary>
        private readonly ConcurrentDictionary<string, AuthorizationCode> authorizationCodes;

        /// <summary>The refresh tokens.</summary>
        private readonly ConcurrentDictionary<string, RefreshToken> refreshTokens;

        /// <summary>The access tokens.</summary>
        private readonly ConcurrentDictionary<string, AccessToken> accessTokens;

        /// <summary>
        /// Initializes a new instance of the Sentinel.OAuth.Implementation.MemoryTokenRepository class.
        /// </summary>
        public MemoryTokenRepository()
        {
            this.authorizationCodes = new ConcurrentDictionary<string, AuthorizationCode>();
            this.refreshTokens = new ConcurrentDictionary<string, RefreshToken>();
            this.accessTokens = new ConcurrentDictionary<string, AccessToken>();
        }

        /// <summary>Gets the specified authorization code.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns>The authorization code.</returns>
        public async Task<IAuthorizationCode> GetAuthorizationCode(string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentNullException(nameof(identifier));
            }

            var entry = this.authorizationCodes.FirstOrDefault(x => x.Key == identifier.ToString());

            return entry.Value;
        }

        /// <summary>
        /// Gets all authorization codes that matches the specified redirect uri and expires after the
        /// specified date.
        /// </summary>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The authorization codes.</returns>
        public async Task<IEnumerable<IAuthorizationCode>> GetAuthorizationCodes(string redirectUri, DateTimeOffset expires)
        {
            return this.authorizationCodes.Where(x => x.Value.RedirectUri == redirectUri && x.Value.ValidTo > expires).Select(x => x.Value);
        }

        /// <summary>Inserts the specified authorization code.</summary>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns>The inserted authorization code. <c>null</c> if the insertion was unsuccessful.</returns>
        public async Task<IAuthorizationCode> InsertAuthorizationCode(IAuthorizationCode authorizationCode)
        {
            var code = new AuthorizationCode(authorizationCode);

            if (!code.IsValid())
            {
                throw new ArgumentException($"The authorization code is invalid: {JsonConvert.SerializeObject(code)}", nameof(authorizationCode));
            }

            if (this.authorizationCodes.TryAdd(code.GetIdentifier().ToString(), code))
            {
                return code;
            }

            return null;
        }

        /// <summary>
        /// Deletes the authorization codes that expires before the specified expire date.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted codes.</returns>
        public async Task<int> DeleteAuthorizationCodes(DateTimeOffset expires)
        {
            var i = 0;
            var codes = this.authorizationCodes.Where(x => x.Value.ValidTo <= expires).ToList();

            foreach (var code in codes)
            {
                AuthorizationCode removedCode;
                if (this.authorizationCodes.TryRemove(code.Key, out removedCode))
                {
                    i++;
                }
            }

            return i;
        }

        /// <summary>Deletes the specified authorization code.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAuthorizationCode(string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentNullException(nameof(identifier));
            }

            var exists = this.authorizationCodes.Any(x => x.Key == identifier);

            if (exists)
            {
                AuthorizationCode removedCode;
                return this.authorizationCodes.TryRemove(identifier, out removedCode);
            }

            return false;
        }

        /// <summary>Deletes the specified authorization code.</summary>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAuthorizationCode(IAuthorizationCode authorizationCode)
        {
            var exists = this.authorizationCodes.Any(x => x.Key == authorizationCode.GetIdentifier());

            if (exists)
            {
                AuthorizationCode removedCode;
                return this.authorizationCodes.TryRemove(authorizationCode.GetIdentifier(), out removedCode);
            }

            return false;
        }

        /// <summary>Gets the specified access token.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns>The access token.</returns>
        public async Task<IAccessToken> GetAccessToken(string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentNullException(nameof(identifier));
            }

            var entry = this.accessTokens.FirstOrDefault(x => x.Key == identifier.ToString());

            return entry.Value;
        }

        /// <summary>Gets all access tokens that expires after the specified date.</summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The access tokens.</returns>
        public async Task<IEnumerable<IAccessToken>> GetAccessTokens(DateTimeOffset expires)
        {
            return this.accessTokens.Select(x => x.Value).Where(x => x.ValidTo > expires);
        }

        /// <summary>
        /// Gets all access tokens for the specified user that expires **after** the specified date. 
        /// Called when authenticating an access token to limit the number of tokens to go through when validating the hash.
        /// </summary>
        /// <param name="subject">The subject.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The access tokens.</returns>
        public async Task<IEnumerable<IAccessToken>> GetAccessTokens(string subject, DateTimeOffset expires)
        {
            return this.accessTokens.Select(x => x.Value).Where(x => x.ValidTo > expires && x.Subject == subject);
        }

        /// <summary>Inserts the specified access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The inserted access token. <c>null</c> if the insertion was unsuccessful.</returns>
        public async Task<IAccessToken> InsertAccessToken(IAccessToken accessToken)
        {
            var token = new AccessToken(accessToken);

            if (!token.IsValid())
            {
                throw new ArgumentException($"The access token is invalid: {JsonConvert.SerializeObject(token)}", nameof(accessToken));
            }

            if (this.accessTokens.TryAdd(token.GetIdentifier(), token))
            {
                return token;
            }

            return null;
        }

        /// <summary>
        /// Deletes the access tokens that expires before the specified expire date. combination.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<int> DeleteAccessTokens(DateTimeOffset expires)
        {
            var i = 0;
            var tokens = this.accessTokens.Where(x => x.Value.ValidTo <= expires).ToList();

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

        /// <summary>Deletes the access tokens belonging to the specified client, redirect uri and subject.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="subject">The subject.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<int> DeleteAccessTokens(string clientId, string redirectUri, string subject)
        {
            var i = 0;
            var tokens = this.accessTokens.Where(x => x.Value.ClientId == clientId && x.Value.RedirectUri == redirectUri && x.Value.Subject == subject).ToList();

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

        /// <summary>Deletes the specified access token.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAccessToken(string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentNullException(nameof(identifier));
            }

            var i = 0;
            var tokens = this.accessTokens.Where(x => x.Key == identifier).ToList();

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

        /// <summary>Deletes the specified access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAccessToken(IAccessToken accessToken)
        {
            var token = this.accessTokens.FirstOrDefault(x => x.Key == accessToken.Token);

            if (token.Value != null)
            {
                AccessToken removedToken;
                return this.accessTokens.TryRemove(token.Key, out removedToken);
            }

            return false;
        }

        /// <summary>Gets the specified refresh token.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns>The refresh token.</returns>
        public async Task<IRefreshToken> GetRefreshToken(string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentNullException(nameof(identifier));
            }

            var entry = this.refreshTokens.FirstOrDefault(x => x.Key == identifier.ToString());

            return entry.Value;
        }

        /// <summary>
        /// Gets all refresh tokens for the specified client id that expires after the specified date.
        /// Called when authentication a refresh token to limit the number of tokens to go through when
        /// validating the hash.
        /// </summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The refresh tokens.</returns>
        public async Task<IEnumerable<IRefreshToken>> GetClientRefreshTokens(string clientId, DateTimeOffset expires)
        {
            return this.refreshTokens.Select(x => x.Value).Where(x => x.ClientId == clientId && x.ValidTo > expires);
        }

        /// <summary>
        /// Gets all refresh tokens for the specified user that expires **after** the specified date. 
        /// </summary>
        /// <param name="subject">The subject.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The refresh tokens.</returns>
        public async Task<IEnumerable<IRefreshToken>> GetUserRefreshTokens(string subject, DateTimeOffset expires)
        {
            return this.refreshTokens.Select(x => x.Value).Where(x => x.Subject == subject && x.ValidTo > expires);
        }

        /// <summary>Inserts the specified refresh token.</summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>
        ///     The inserted refresh token. <c>null</c> if the insertion was unsuccessful.
        /// </returns>
        public async Task<IRefreshToken> InsertRefreshToken(IRefreshToken refreshToken)
        {
            var token = (RefreshToken)refreshToken;

            if (!token.IsValid())
            {
                throw new ArgumentException($"The refresh token is invalid: {JsonConvert.SerializeObject(token)}", nameof(refreshToken));
            }

            if (this.refreshTokens.TryAdd(token.GetIdentifier().ToString(), token))
            {
                return refreshToken;
            }

            return null;
        }

        /// <summary>
        /// Deletes the refresh tokens that expires before the specified expire date. combination.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<int> DeleteRefreshTokens(DateTimeOffset expires)
        {
            var i = 0;
            var tokens = this.refreshTokens.Where(x => x.Value.ValidTo <= expires).ToList();

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

        /// <summary>Deletes the refresh tokens belonging to the specified client, redirect uri and subject.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="subject">The subject.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<int> DeleteRefreshTokens(string clientId, string redirectUri, string subject)
        {
            var i = 0;
            var tokens = this.refreshTokens.Where(x => x.Value.ClientId == clientId && x.Value.RedirectUri == redirectUri && x.Value.Subject == subject).ToList();

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

        /// <summary>Deletes the specified refresh token.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteRefreshToken(string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentNullException(nameof(identifier));
            }

            var exists = this.refreshTokens.Any(x => x.Key == identifier.ToString());

            if (exists)
            {
                var token = this.refreshTokens.First(x => x.Key == identifier.ToString());

                RefreshToken removedToken;
                return this.refreshTokens.TryRemove(token.Key, out removedToken);
            }

            return false;
        }

        /// <summary>Deletes all access tokens, refresh tokens and authorization codes.</summary>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> Purge()
        {
            this.authorizationCodes.Clear();
            this.refreshTokens.Clear();
            this.accessTokens.Clear();

            return true;
        }
    }
}