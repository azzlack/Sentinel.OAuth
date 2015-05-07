namespace Sentinel.OAuth.TokenManagers.RedisTokenRepository.Implementation
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;

    using Newtonsoft.Json;

    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Models.OAuth;
    using Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models;

    using StackExchange.Redis;

    /// <summary>A token repository using Redis for storage.</summary>
    public class RedisTokenRepository : ITokenRepository
    {
        /// <summary>The configuration.</summary>
        private readonly RedisTokenRepositoryConfiguration configuration;

        /// <summary>
        /// Initializes a new instance of the RedisTokenRepository class.
        /// </summary>
        /// <param name="configuration">The configuration.</param>
        public RedisTokenRepository(RedisTokenRepositoryConfiguration configuration)
        {
            this.configuration = configuration;
        }

        /// <summary>
        /// Gets all authorization codes that matches the specified redirect uri and expires after the
        /// specified date. Called when authenticating an authorization code.
        /// </summary>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The authorization codes.</returns>
        public async Task<IEnumerable<IAuthorizationCode>> GetAuthorizationCodes(string redirectUri, DateTime expires)
        {
            var db = this.GetDatabase();

            var hashes = db.HashScan("sentinel.oauth:authorizationcodes");
            var codes = new List<AuthorizationCode>();

            foreach (var hash in hashes)
            {
                var code = JsonConvert.DeserializeObject<AuthorizationCode>(hash.Value);

                if (code.RedirectUri == redirectUri && code.ValidTo > expires)
                {
                    codes.Add(code);
                }
            }

            return codes;
        }

        /// <summary>
        /// Inserts the specified authorization code. Called when creating an authorization code.
        /// </summary>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns>
        /// The inserted authorization code. <c>null</c> if the insertion was unsuccessful.
        /// </returns>
        public async Task<IAuthorizationCode> InsertAuthorizationCode(IAuthorizationCode authorizationCode)
        {
            var key = string.Format("{0}_{1}_{2}", authorizationCode.ClientId, authorizationCode.RedirectUri, authorizationCode.Subject);

            var db = this.GetDatabase();
            
            // Add value to database
            var result = await db.HashSetAsync("sentinel.oauth:authorizationcodes", key, JsonConvert.SerializeObject(authorizationCode));

            if (result)
            {
                return authorizationCode;
            }

            return null;
        }

        /// <summary>
        /// Deletes the authorization codes that belongs to the specified client, redirect uri and user
        /// combination. Called when creating an authorization code to prevent duplicate authorization
        /// codes.
        /// </summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="userId">Identifier for the user.</param>
        /// <returns>The number of deleted codes.</returns>
        public async Task<int> DeleteAuthorizationCodes(string clientId, string redirectUri, string userId)
        {
            var key = string.Format("{0}_{1}_{2}", clientId, redirectUri, userId);

            var db = this.GetDatabase();
            var success = await db.HashDeleteAsync("sentinel.oauth:authorizationcodes", key);

            return success ? 1 : 0;
        }

        /// <summary>
        /// Deletes the authorization codes that expires before the specified expire date. Called when
        /// creating an authorization code to cleanup.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted codes.</returns>
        public async Task<int> DeleteAuthorizationCodes(DateTime expires)
        {
            var db = this.GetDatabase();

            var i = 0;
            var hashes = db.HashScan("sentinel.oauth:authorizationcodes");

            foreach (var hash in hashes)
            {
                var code = JsonConvert.DeserializeObject<AuthorizationCode>(hash.Value);

                if (code.ValidTo < expires)
                {
                    var key = string.Format("{0}_{1}_{2}", code.ClientId, code.RedirectUri, code.Subject);

                    await db.HashDeleteAsync("sentinel.oauth:authorizationcodes", key);

                    i++;
                }
            }

            return i;
        }

        /// <summary>
        /// Deletes the specified authorization code. Called when authenticating an authorization code to
        /// prevent re-use.
        /// </summary>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAuthorizationCode(IAuthorizationCode authorizationCode)
        {
            var key = string.Format("{0}_{1}_{2}", authorizationCode.ClientId, authorizationCode.RedirectUri, authorizationCode.Subject);

            var db = this.GetDatabase();

            return await db.HashDeleteAsync("sentinel.oauth:authorizationcodes", key);
        }

        /// <summary>
        /// Gets all access tokens that expires **after** the specified date. Called when authenticating
        /// an access token to limit the number of tokens to go through when validating the hash.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The access tokens.</returns>
        public async Task<IEnumerable<IAccessToken>> GetAccessTokens(DateTime expires)
        {
            var db = this.GetDatabase();

            var hashes = db.HashScan("sentinel.oauth:accesstokens");
            var tokens = new List<AccessToken>();

            foreach (var hash in hashes)
            {
                var token = JsonConvert.DeserializeObject<AccessToken>(hash.Value);

                if (token.ValidTo > expires)
                {
                    tokens.Add(token);
                }
            }

            return tokens;
        }

        /// <summary>Inserts the specified access token. Called when creating an access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The inserted access token. <c>null</c> if the insertion was unsuccessful.</returns>
        public async Task<IAccessToken> InsertAccessToken(IAccessToken accessToken)
        {
            var key = string.Format("{0}_{1}_{2}", accessToken.ClientId, accessToken.RedirectUri, accessToken.Subject);

            var db = this.GetDatabase();

            // Add value to database
            var result = await db.HashSetAsync("sentinel.oauth:accesstokens", key, JsonConvert.SerializeObject(accessToken));

            if (result)
            {
                return accessToken;
            }

            return null;
        }

        /// <summary>
        /// Deletes the access tokens that belongs to the specified client, redirect uri and user
        /// combination. Called when creating an access token to prevent duplicate access tokens.
        /// </summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="userId">Identifier for the user.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<int> DeleteAccessTokens(string clientId, string redirectUri, string userId)
        {
            var key = string.Format("{0}_{1}_{2}", clientId, redirectUri, userId);

            var db = this.GetDatabase();
            var success = await db.HashDeleteAsync("sentinel.oauth:accesstokens", key);

            return success ? 1 : 0;
        }

        /// <summary>
        /// Deletes the access tokens that expires before the specified expire date. Called when creating
        /// an access token to cleanup.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<int> DeleteAccessTokens(DateTime expires)
        {
            var db = this.GetDatabase();

            var i = 0;
            var hashes = db.HashScan("sentinel.oauth:accesstokens");

            foreach (var hash in hashes)
            {
                var code = JsonConvert.DeserializeObject<AccessToken>(hash.Value);

                if (code.ValidTo < expires)
                {
                    var key = string.Format("{0}_{1}_{2}", code.ClientId, code.RedirectUri, code.Subject);

                    await db.HashDeleteAsync("sentinel.oauth:accesstokens", key);

                    i++;
                }
            }

            return i;
        }

        /// <summary>
        /// Gets all refresh tokens that matches the specified redirect uri and expires after the
        /// specified date. Called when authentication a refresh token to limit the number of tokens to
        /// go through when validating the hash.
        /// </summary>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The refresh tokens.</returns>
        public async Task<IEnumerable<IRefreshToken>> GetRefreshTokens(string redirectUri, DateTime expires)
        {
            var db = this.GetDatabase();

            var hashes = db.HashScan("sentinel.oauth:refreshtokens");
            var tokens = new List<RefreshToken>();

            foreach (var hash in hashes)
            {
                var token = JsonConvert.DeserializeObject<RefreshToken>(hash.Value);

                if (token.RedirectUri == redirectUri && token.ValidTo > expires)
                {
                    tokens.Add(token);
                }
            }

            return tokens;
        }

        /// <summary>Inserts the specified refresh token. Called when creating a refresh token.</summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>The inserted refresh token. <c>null</c> if the insertion was unsuccessful.</returns>
        public async Task<IRefreshToken> InsertRefreshToken(IRefreshToken refreshToken)
        {
            var key = string.Format("{0}_{1}_{2}", refreshToken.ClientId, refreshToken.RedirectUri, refreshToken.Subject);

            var db = this.GetDatabase();

            // Add value to database
            var result = await db.HashSetAsync("sentinel.oauth:refreshtokens", key, JsonConvert.SerializeObject(refreshToken));

            if (result)
            {
                return refreshToken;
            }

            return null;
        }

        /// <summary>
        /// Deletes the refresh tokens that belongs to the specified client, redirect uri and user
        /// combination. Called when creating a refresh token to prevent duplicate refresh tokens.
        /// </summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="userId">Identifier for the user.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<int> DeleteRefreshTokens(string clientId, string redirectUri, string userId)
        {
            var key = string.Format("{0}_{1}_{2}", clientId, redirectUri, userId);

            var db = this.GetDatabase();
            var success = await db.HashDeleteAsync("sentinel.oauth:refreshtokens", key);

            return success ? 1 : 0;
        }

        /// <summary>
        /// Deletes the refresh tokens that expires before the specified expire date. Called when
        /// creating a refresh token to cleanup.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<int> DeleteRefreshTokens(DateTime expires)
        {
            var db = this.GetDatabase();

            var i = 0;
            var hashes = db.HashScan("sentinel.oauth:refreshtokens");

            foreach (var hash in hashes)
            {
                var code = JsonConvert.DeserializeObject<RefreshToken>(hash.Value);

                if (code.ValidTo < expires)
                {
                    var key = string.Format("{0}_{1}_{2}", code.ClientId, code.RedirectUri, code.Subject);

                    await db.HashDeleteAsync("sentinel.oauth:refreshtokens", key);

                    i++;
                }
            }

            return i;
        }

        /// <summary>
        /// Deletes the specified refresh token. Called when authenticating a refresh token to prevent re-
        /// use.
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteRefreshToken(IRefreshToken refreshToken)
        {
            var key = string.Format("{0}_{1}_{2}", refreshToken.ClientId, refreshToken.RedirectUri, refreshToken.Subject);

            var db = this.GetDatabase();

            return await db.HashDeleteAsync("sentinel.oauth:refreshtokens", key);
        }

        /// <summary>Gets a reference to the database.</summary>
        /// <returns>A reference to database.</returns>
        private IDatabase GetDatabase()
        {
            return this.configuration.Connection.GetDatabase(this.configuration.Database);
        }
    }
}