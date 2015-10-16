namespace Sentinel.OAuth.TokenManagers.RedisTokenRepository.Implementation
{
    using Newtonsoft.Json;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Extensions;
    using Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models;
    using StackExchange.Redis;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    /// <summary>A token repository using Redis for storage.</summary>
    public class RedisTokenRepository : ITokenRepository
    {
        /// <summary>The date time maximum.</summary>
        private const double DateTimeMax = 253402300800.0;

        /// <summary>
        /// Initializes a new instance of the RedisTokenRepository class.
        /// </summary>
        /// <param name="configuration">The configuration.</param>
        public RedisTokenRepository(RedisTokenRepositoryConfiguration configuration)
        {
            this.Configuration = configuration;
        }

        /// <summary>Gets the configuration.</summary>
        /// <value>The configuration.</value>
        protected RedisTokenRepositoryConfiguration Configuration { get; private set; }

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

            var min = expires.ToUnixTime();
            var codes = new List<IAuthorizationCode>();

            var keys = db.SortedSetRangeByScore($"{this.Configuration.AuthorizationCodePrefix}:_index:expires", min, DateTimeMax);

            foreach (var key in keys)
            {
                var hashedId = key.ToString().Substring(this.Configuration.AuthorizationCodePrefix.Length + 1);
                var id = Encoding.UTF8.GetString(Convert.FromBase64String(hashedId));

                if (id.Contains(redirectUri))
                {
                    var hashEntries = await db.HashGetAllAsync(key.ToString());

                    if (hashEntries.Any())
                    {
                        var code = new RedisAuthorizationCode(hashEntries) { Id = hashedId };

                        codes.Add(code);
                    }
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
            var code = new RedisAuthorizationCode(authorizationCode);

            if (!code.IsValid())
            {
                throw new ArgumentException($"The authorization code is invalid: {JsonConvert.SerializeObject(code)}", nameof(authorizationCode));
            }

            var key = this.GenerateKey(code);

            var db = this.GetDatabase();
            var tran = db.CreateTransaction();

            try
            {
                this.Configuration.Log.DebugFormat("Inserting access token hash in key {0}", key);

                // Add hash to key
                tran.HashSetAsync(key, code.ToHashEntries());

                var expires = authorizationCode.ValidTo.ToUnixTime();

                this.Configuration.Log.DebugFormat("Inserting key {0} to authorization code set with score {1}", key, expires);

                // Add key to sorted set for future reference. The score is the expire time in seconds since epoch.
                tran.SortedSetAddAsync($"{this.Configuration.AuthorizationCodePrefix}:_index:expires", key, expires);

                this.Configuration.Log.DebugFormat("Making key {0} expire at {1}", key, authorizationCode.ValidTo);

                // Make the key expire when the code times out
                tran.KeyExpireAsync(key, authorizationCode.ValidTo);

                await tran.ExecuteAsync();

                return authorizationCode;
            }
            catch (Exception ex)
            {
                this.Configuration.Log.Error("Error when inserting authorization code", ex);
            }

            return null;
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
            var tran = db.CreateTransaction();

            var keysToDelete = await db.SortedSetRangeByScoreAsync($"{this.Configuration.AuthorizationCodePrefix}:_index:expires", 0, expires.ToUnixTime());

            // Remove items from index
            var expireTask = tran.SortedSetRemoveRangeByScoreAsync($"{this.Configuration.AuthorizationCodePrefix}:_index:expires", 0, expires.ToUnixTime());

            // Remove keys
            foreach (var key in keysToDelete)
            {
                tran.KeyDeleteAsync(key.ToString());
            }

            await tran.ExecuteAsync(CommandFlags.HighPriority);

            return (int)expireTask.Result;
        }

        /// <summary>
        /// Deletes the specified authorization code. Called when authenticating an authorization code to
        /// prevent re-use.
        /// </summary>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAuthorizationCode(IAuthorizationCode authorizationCode)
        {
            var code = new RedisAuthorizationCode(authorizationCode);

            var key = this.GenerateKey(code);

            var db = this.GetDatabase();
            var tran = db.CreateTransaction();

            // Remove items from index
            tran.SortedSetRemoveAsync(this.Configuration.AuthorizationCodePrefix, key);

            // Remove key
            tran.KeyDeleteAsync(key);

            return await tran.ExecuteAsync(CommandFlags.HighPriority);
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

            var min = expires.ToUnixTime();
            var tokens = new List<IAccessToken>();

            var expiresKeys = await db.SortedSetRangeByScoreAsync($"{this.Configuration.AccessTokenPrefix}:_index:expires", min, DateTimeMax);

            foreach (var key in expiresKeys)
            {
                var hashedId = key.ToString().Substring(this.Configuration.AccessTokenPrefix.Length + 1);

                var hashEntries = await db.HashGetAllAsync(key.ToString());

                if (hashEntries.Any())
                {
                    var token = new RedisAccessToken(hashEntries) { Id = hashedId };

                    tokens.Add(token);
                }
            }

            return tokens;
        }

        /// <summary>
        /// Gets all access tokens for the specified user that expires **after** the specified date. 
        /// Called when authenticating an access token to limit the number of tokens to go through when validating the hash.
        /// </summary>
        /// <param name="subject">The subject.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The access tokens.</returns>
        public async Task<IEnumerable<IAccessToken>> GetAccessTokens(string subject, DateTime expires)
        {
            var db = this.GetDatabase();

            var min = expires.ToUnixTime();
            var tokens = new List<IAccessToken>();

            var expiresKeys = await db.SortedSetRangeByScoreAsync($"{this.Configuration.AccessTokenPrefix}:_index:expires", min, DateTimeMax);
            var subjectKeys = await db.HashGetAllAsync($"{this.Configuration.AccessTokenPrefix}:_index:subject:{subject}");

            var unionKeys = new List<string>().Join(expiresKeys, x => x, y => y.ToString(), (x, y) => x).Join(subjectKeys, x => x, y => y.Value.ToString(), (x, y) => x);

            foreach (var key in unionKeys)
            {
                var hashedId = key.Substring(this.Configuration.AccessTokenPrefix.Length + 1);

                var hashEntries = await db.HashGetAllAsync(key);

                if (hashEntries.Any())
                {
                    var token = new RedisAccessToken(hashEntries) { Id = hashedId };

                    tokens.Add(token);
                }
            }

            return tokens.Where(x => x.Subject == subject);
        }

        /// <summary>Inserts the specified access token. Called when creating an access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The inserted access token. <c>null</c> if the insertion was unsuccessful.</returns>
        public async Task<IAccessToken> InsertAccessToken(IAccessToken accessToken)
        {
            var token = new RedisAccessToken(accessToken);

            // Validate token
            if (!token.IsValid())
            {
                throw new ArgumentException($"The access token is invalid: {JsonConvert.SerializeObject(token)}", nameof(accessToken));
            }

            var key = this.GenerateKey(token);

            var db = this.GetDatabase();
            var tran = db.CreateTransaction();

            try
            {
                this.Configuration.Log.DebugFormat("Inserting access token hash in key {0}", key);

                // Add hash to key
                tran.HashSetAsync(key, token.ToHashEntries());

                var expires = accessToken.ValidTo.ToUnixTime();

                this.Configuration.Log.DebugFormat("Inserting key {0} to access token set with score {1}", key, expires);

                // Add key to sorted set for future reference by expire time. The score is the expire time in seconds since epoch.
                tran.SortedSetAddAsync($"{this.Configuration.AccessTokenPrefix}:_index:expires", key, expires);

                // Add key to hashed set for future reference by client id, redirect uri or subject. The value is the expire time in seconds since epoch.
                tran.HashSetAsync($"{this.Configuration.AccessTokenPrefix}:_index:client:{token.ClientId}", key, expires);
                tran.HashSetAsync($"{this.Configuration.AccessTokenPrefix}:_index:redirecturi:{token.RedirectUri}", key, expires);
                tran.HashSetAsync($"{this.Configuration.AccessTokenPrefix}:_index:subject:{token.Subject}", key, expires);

                this.Configuration.Log.DebugFormat("Making key {0} expire at {1}", key, accessToken.ValidTo);

                // Make the keys expire when the code times out
                tran.KeyExpireAsync(key, accessToken.ValidTo);

                await tran.ExecuteAsync();

                return accessToken;
            }
            catch (Exception ex)
            {
                this.Configuration.Log.Error("Error when inserting access token", ex);
            }

            return null;
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
            var tran = db.CreateTransaction();

            var keysToDelete = await db.SortedSetRangeByScoreAsync($"{this.Configuration.AccessTokenPrefix}:_index:expires", 0, expires.ToUnixTime());

            // Remove items from indexes
            tran.SortedSetRemoveRangeByScoreAsync($"{this.Configuration.AccessTokenPrefix}:_index:expires", 0, expires.ToUnixTime());

            // Remove items
            foreach (var key in keysToDelete)
            {
                var data = await db.HashGetAllAsync(key.ToString());
                var token = new RedisAccessToken(data);

                tran.HashDeleteAsync($"{this.Configuration.AccessTokenPrefix}:_index:client:{token.ClientId}", key);
                tran.HashDeleteAsync($"{this.Configuration.AccessTokenPrefix}:_index:redirecturi:{token.RedirectUri}", key);
                tran.HashDeleteAsync($"{this.Configuration.AccessTokenPrefix}:_index:subject:{token.Subject}", key);
                tran.KeyDeleteAsync(key.ToString());
            }

            await tran.ExecuteAsync(CommandFlags.HighPriority);

            return keysToDelete.Length;
        }

        /// <summary>
        /// Deletes the access tokens belonging to the specified client, redirect uri and subject.
        /// </summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="subject">The subject.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<int> DeleteAccessTokens(string clientId, string redirectUri, string subject)
        {
            var db = this.GetDatabase();
            var tran = db.CreateTransaction();

            var clientKeys = db.HashGetAll($"{this.Configuration.AccessTokenPrefix}:_index:client:{clientId}");
            var redirectUriKeys = db.HashGetAll($"{this.Configuration.AccessTokenPrefix}:_index:redirecturi:{redirectUri}");
            var subjectKeys = db.HashGetAll($"{this.Configuration.AccessTokenPrefix}:_index:subject:{subject}");

            var unionKeys =
                new List<HashEntry>()
                    .Join(clientKeys, x => x.Name, y => y.Name, (x, y) => x)
                    .Join(redirectUriKeys, x => x.Name, y => y.Name, (x, y) => x)
                    .Join(subjectKeys, x => x.Name, y => y.Name, (x, y) => x);

            // Remove keys
            foreach (var key in unionKeys)
            {
                var data = await db.HashGetAllAsync(key.ToString());
                var token = new RedisAccessToken(data);

                // Remove items from indexes
                tran.SortedSetRemoveAsync($"{this.Configuration.AccessTokenPrefix}:_index:expires", key.ToString());
                tran.HashDeleteAsync($"{this.Configuration.AccessTokenPrefix}:_index:client:{token.ClientId}", key.ToString());
                tran.HashDeleteAsync($"{this.Configuration.AccessTokenPrefix}:_index:redirecturi:{token.RedirectUri}", key.ToString());
                tran.HashDeleteAsync($"{this.Configuration.AccessTokenPrefix}:_index:subject:{token.Subject}", key.ToString());

                // Remove key
                tran.KeyDeleteAsync(key.ToString());
            }

            await tran.ExecuteAsync(CommandFlags.HighPriority);

            return unionKeys.Count();
        }

        /// <summary>Deletes the specified access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAccessToken(IAccessToken accessToken)
        {
            var token = new RedisAccessToken(accessToken);

            var key = this.GenerateKey(token);

            var db = this.GetDatabase();
            var tran = db.CreateTransaction();

            // Remove items from indexes
            tran.HashDeleteAsync($"{this.Configuration.AccessTokenPrefix}:_index:client:{token.ClientId}", key);
            tran.HashDeleteAsync($"{this.Configuration.AccessTokenPrefix}:_index:redirecturi:{token.RedirectUri}", key);
            tran.HashDeleteAsync($"{this.Configuration.AccessTokenPrefix}:_index:subject:{token.Subject}", key);
            tran.SortedSetRemoveAsync($"{this.Configuration.AccessTokenPrefix}:_index:expires", key);

            // Remove key
            tran.KeyDeleteAsync(key, CommandFlags.HighPriority);

            var commited = await tran.ExecuteAsync(CommandFlags.HighPriority);

            return commited;
        }

        /// <summary>
        /// Gets all refresh tokens that matches the specified redirect uri and expires after the
        /// specified date. Called when authentication a refresh token to limit the number of tokens to
        /// go through when validating the hash.
        /// </summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The refresh tokens.</returns>
        public async Task<IEnumerable<IRefreshToken>> GetRefreshTokens(string clientId, string redirectUri, DateTime expires)
        {
            var db = this.GetDatabase();

            var min = expires.ToUnixTime();
            var tokens = new List<IRefreshToken>();

            var keys = db.SortedSetRangeByScore(this.Configuration.RefreshTokenPrefix, min, DateTimeMax);

            foreach (var key in keys)
            {
                var hashedId = key.ToString().Substring(this.Configuration.RefreshTokenPrefix.Length + 1);

                var hashEntries = await db.HashGetAllAsync(key.ToString());

                if (hashEntries.Any())
                {
                    var token = new RedisRefreshToken(hashEntries) { Id = hashedId };

                    if (token.ClientId == clientId && token.RedirectUri == redirectUri)
                    {
                        tokens.Add(token);
                    }
                }
            }

            return tokens;
        }

        /// <summary>Inserts the specified refresh token. Called when creating a refresh token.</summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>The inserted refresh token. <c>null</c> if the insertion was unsuccessful.</returns>
        public async Task<IRefreshToken> InsertRefreshToken(IRefreshToken refreshToken)
        {
            var token = new RedisRefreshToken(refreshToken);

            if (!token.IsValid())
            {
                throw new ArgumentException($"The refresh token is invalid: {JsonConvert.SerializeObject(token)}", nameof(refreshToken));
            }

            var key = this.GenerateKey(token);

            var db = this.GetDatabase();
            var tran = db.CreateTransaction();

            try
            {
                this.Configuration.Log.DebugFormat("Inserting refresh token hash in key {0}", key);

                // Add hash to key
                tran.HashSetAsync(key, token.ToHashEntries());

                var expires = refreshToken.ValidTo.ToUnixTime();

                this.Configuration.Log.DebugFormat("Inserting key {0} to refresh token set with score {1}", key, expires);

                // Add key to index for future reference. The score is the expire time in seconds since epoch.
                tran.SortedSetAddAsync(this.Configuration.RefreshTokenPrefix, key, expires);

                // Add key to hashed set for future reference by client id, redirect uri or subject. The value is the expire time in seconds since epoch.
                tran.HashSetAsync($"{this.Configuration.RefreshTokenPrefix}:_index:client:{token.ClientId}", key, expires);
                tran.HashSetAsync($"{this.Configuration.RefreshTokenPrefix}:_index:redirecturi:{token.RedirectUri}", key, expires);
                tran.HashSetAsync($"{this.Configuration.RefreshTokenPrefix}:_index:subject:{token.Subject}", key, expires);

                this.Configuration.Log.DebugFormat("Making key {0} expire at {1}", key, refreshToken.ValidTo);

                // Make the key expire when the code times out
                tran.KeyExpireAsync(key, refreshToken.ValidTo);

                await tran.ExecuteAsync();

                return refreshToken;
            }
            catch (Exception ex)
            {
                this.Configuration.Log.Error("Error when inserting refresh token", ex);
            }

            return null;
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
            var tran = db.CreateTransaction();

            var keysToDelete = await db.SortedSetRangeByScoreAsync($"{this.Configuration.RefreshTokenPrefix}:_index:expires", 0, expires.ToUnixTime());

            // Remove items from indexes
            tran.SortedSetRemoveRangeByScoreAsync($"{this.Configuration.RefreshTokenPrefix}:_index:expires", 0, expires.ToUnixTime());

            // Remove items
            foreach (var key in keysToDelete)
            {
                var data = await db.HashGetAllAsync(key.ToString());
                var token = new RedisRefreshToken(data);

                tran.HashDeleteAsync($"{this.Configuration.RefreshTokenPrefix}:_index:client:{token.ClientId}", key);
                tran.HashDeleteAsync($"{this.Configuration.RefreshTokenPrefix}:_index:redirecturi:{token.RedirectUri}", key);
                tran.HashDeleteAsync($"{this.Configuration.RefreshTokenPrefix}:_index:subject:{token.Subject}", key);
                tran.KeyDeleteAsync(key.ToString());
            }

            await tran.ExecuteAsync(CommandFlags.HighPriority);

            return keysToDelete.Length;
        }

        /// <summary>
        /// Deletes the specified refresh token. Called when authenticating a refresh token to prevent re-
        /// use.
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteRefreshToken(IRefreshToken refreshToken)
        {
            var token = new RedisRefreshToken(refreshToken);

            var key = this.GenerateKey(token);

            var db = this.GetDatabase();
            var tran = db.CreateTransaction();

            // Remove items from indexes
            tran.SortedSetRemoveAsync($"{this.Configuration.RefreshTokenPrefix}:_index:expires", key);
            tran.HashDeleteAsync($"{this.Configuration.RefreshTokenPrefix}:_index:client:{token.ClientId}", key);
            tran.HashDeleteAsync($"{this.Configuration.RefreshTokenPrefix}:_index:redirecturi:{token.RedirectUri}", key);
            tran.HashDeleteAsync($"{this.Configuration.RefreshTokenPrefix}:_index:subject:{token.Subject}", key);

            // Remove keys
            tran.KeyDeleteAsync(key);

            return await tran.ExecuteAsync(CommandFlags.HighPriority);
        }

        /// <summary>Deletes all access tokens, refresh tokens and authorization codes.</summary>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> Purge()
        {
            var server = this.Configuration.Connection.GetServer(this.Configuration.Connection.GetEndPoints().First());

            await server.FlushDatabaseAsync();

            return true;
        }

        /// <summary>Generates a key.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The key.</returns>
        protected string GenerateKey(RedisAccessToken accessToken)
        {
            return this.Configuration.AccessTokenPrefix + ":" + accessToken.Id;
        }

        /// <summary>Generates a key.</summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>The key.</returns>
        protected string GenerateKey(RedisRefreshToken refreshToken)
        {
            return this.Configuration.RefreshTokenPrefix + ":" + refreshToken.Id;
        }

        /// <summary>Generates a key.</summary>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns>The key.</returns>
        protected string GenerateKey(RedisAuthorizationCode authorizationCode)
        {
            return this.Configuration.AuthorizationCodePrefix + ":" + authorizationCode.Id;
        }

        /// <summary>Gets a reference to the database.</summary>
        /// <returns>A reference to database.</returns>
        protected virtual IDatabase GetDatabase()
        {
            return this.Configuration.Connection.GetDatabase(this.Configuration.Database);
        }
    }
}