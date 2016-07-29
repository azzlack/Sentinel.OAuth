namespace Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Implementation
{
    using Raven.Abstractions.Data;
    using Raven.Client;
    using Raven.Client.Document;
    using Raven.Client.Linq;
    using Raven.Imports.Newtonsoft.Json;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models;
    using Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models.OAuth;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;

    /// <summary>A token repository using RavenDB for storage.</summary>
    public class RavenDbTokenRepository : ITokenRepository
    {
        /// <summary>
        /// Initializes a new instance of the
        /// Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Implementation.RavenDbTokenRepository
        /// class.
        /// </summary>
        /// <param name="configuration">The configuration.</param>
        public RavenDbTokenRepository(RavenDbTokenRepositoryConfiguration configuration)
        {
            this.Configuration = configuration;
        }

        /// <summary>Gets the configuration.</summary>
        /// <value>The configuration.</value>
        protected RavenDbTokenRepositoryConfiguration Configuration { get; }

        /// <summary>Gets the specified authorization code.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns>The authorization code.</returns>
        public async Task<IAuthorizationCode> GetAuthorizationCode(object identifier)
        {
            if (identifier == null)
            {
                throw new ArgumentNullException(nameof(identifier));
            }

            using (var session = this.OpenAsyncSession())
            {
                return await
                    session.Query<RavenAuthorizationCode>()
                        .Customize(x => x.WaitForNonStaleResultsAsOfLastWrite())
                        .Where(x => x.Code == identifier)
                        .FirstOrDefaultAsync();
            }
        }

        /// <summary>
        /// Gets all authorization codes that matches the specified redirect uri and expires after the
        /// specified date. Called when authenticating an authorization code.
        /// </summary>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The authorization codes.</returns>
        public async Task<IEnumerable<IAuthorizationCode>> GetAuthorizationCodes(string redirectUri, DateTimeOffset expires)
        {
            using (var session = this.OpenAsyncSession())
            {
                return
                    await
                    session.Query<RavenAuthorizationCode>()
                        .Customize(x => x.WaitForNonStaleResultsAsOfLastWrite())
                        .Where(x => x.RedirectUri == redirectUri && x.ValidTo > expires)
                        .ToListAsync();
            }
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
            var code = new RavenAuthorizationCode(authorizationCode);

            // Validate token
            if (!code.IsValid())
            {
                throw new ArgumentException($"The authorization code is invalid: {JsonConvert.SerializeObject(code)}", nameof(authorizationCode));
            }

            using (var session = this.OpenAsyncSession())
            {
                await session.StoreAsync(code);
                await session.SaveChangesAsync();

                return code;
            }
        }

        /// <summary>
        /// Deletes the authorization codes that expires before the specified expire date. Called when
        /// creating an authorization code to cleanup.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted codes.</returns>
        public async Task<int> DeleteAuthorizationCodes(DateTimeOffset expires)
        {
            using (var session = this.OpenAsyncSession())
            {
                var i = 0;
                var matches =
                    await
                    session.Query<RavenAuthorizationCode>()
                        .Customize(x => x.WaitForNonStaleResultsAsOfLastWrite())
                        .Where(x => x.ValidTo <= expires)
                        .ToListAsync();

                foreach (var match in matches)
                {
                    session.Delete(match);
                    i++;
                }

                if (i > 0)
                {
                    await session.SaveChangesAsync();
                }

                return i;
            }
        }

        /// <summary>Deletes the specified authorization code.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAuthorizationCode(object identifier)
        {
            if (identifier == null)
            {
                throw new ArgumentNullException(nameof(identifier));
            }

            using (var session = this.OpenAsyncSession())
            {
                var match = await
                    session.Query<RavenAuthorizationCode>()
                        .Customize(x => x.WaitForNonStaleResultsAsOfLastWrite())
                        .Where(x => x.Code == identifier)
                        .FirstOrDefaultAsync();

                session.Delete(match);
                await session.SaveChangesAsync();

                return true;
            }
        }

        /// <summary>Deletes the specified authorization code.</summary>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAuthorizationCode(IAuthorizationCode authorizationCode)
        {
            using (var session = this.OpenAsyncSession())
            {
                var match = await
                    session.Query<RavenAuthorizationCode>()
                        .Customize(x => x.WaitForNonStaleResultsAsOfLastWrite())
                        .Where(x => x.Code == authorizationCode.Code)
                        .FirstOrDefaultAsync();

                session.Delete(match);
                await session.SaveChangesAsync();

                return true;
            }
        }

        /// <summary>Gets the specified access token.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns>The access token.</returns>
        public async Task<IAccessToken> GetAccessToken(object identifier)
        {
            if (identifier == null)
            {
                throw new ArgumentNullException(nameof(identifier));
            }

            using (var session = this.OpenAsyncSession())
            {
                return await
                    session.Query<RavenAccessToken>()
                        .Customize(x => x.WaitForNonStaleResultsAsOfLastWrite())
                        .Where(x => x.Token == identifier)
                        .FirstOrDefaultAsync();
            }
        }

        /// <summary>
        /// Gets all access tokens that expires **after** the specified date. Called when authenticating
        /// an access token to limit the number of tokens to go through when validating the hash.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The access tokens.</returns>
        public async Task<IEnumerable<IAccessToken>> GetAccessTokens(DateTimeOffset expires)
        {
            using (var session = this.OpenAsyncSession())
            {
                return await session.Query<RavenAccessToken>().Customize(x => x.WaitForNonStaleResultsAsOfLastWrite()).Where(x => x.ValidTo > expires).ToListAsync();
            }
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
            using (var session = this.OpenAsyncSession())
            {
                return await session.Query<RavenAccessToken>().Customize(x => x.WaitForNonStaleResultsAsOfLastWrite()).Where(x => x.ValidTo > expires && x.Subject == subject).ToListAsync();
            }
        }

        /// <summary>Inserts the specified access token. Called when creating an access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The inserted access token. <c>null</c> if the insertion was unsuccessful.</returns>
        public async Task<IAccessToken> InsertAccessToken(IAccessToken accessToken)
        {
            var token = new RavenAccessToken(accessToken);

            // Validate token
            if (!token.IsValid())
            {
                throw new ArgumentException($"The access token is invalid: {JsonConvert.SerializeObject(token)}", nameof(accessToken));
            }

            using (var session = this.OpenAsyncSession())
            {
                await session.StoreAsync(token);
                await session.SaveChangesAsync();

                return token;
            }
        }

        /// <summary>
        /// Deletes the access tokens that expires before the specified expire date. Called when creating
        /// an access token to cleanup.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<int> DeleteAccessTokens(DateTimeOffset expires)
        {
            using (var session = this.OpenAsyncSession())
            {
                var i = 0;
                var matches =
                    await
                    session.Query<RavenAccessToken>()
                        .Customize(x => x.WaitForNonStaleResultsAsOfLastWrite())
                        .Where(x => x.ValidTo <= expires)
                        .ToListAsync();

                foreach (var match in matches)
                {
                    session.Delete(match);
                    i++;
                }

                if (i > 0)
                {
                    await session.SaveChangesAsync();
                }

                return i;
            }
        }

        /// <summary>Deletes the access tokens belonging to the specified client, redirect uri and subject.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="subject">The subject.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<int> DeleteAccessTokens(string clientId, string redirectUri, string subject)
        {
            using (var session = this.OpenAsyncSession())
            {
                var i = 0;
                var matches =
                    await
                    session.Query<RavenAccessToken>()
                        .Customize(x => x.WaitForNonStaleResultsAsOfLastWrite())
                        .Where(x => x.ClientId == clientId && x.RedirectUri == redirectUri && x.Subject == subject)
                        .ToListAsync();

                foreach (var match in matches)
                {
                    session.Delete(match);
                    i++;
                }

                if (i > 0)
                {
                    await session.SaveChangesAsync();
                }

                return i;
            }
        }

        /// <summary>Deletes the specified access token.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAccessToken(object identifier)
        {
            if (identifier == null)
            {
                throw new ArgumentNullException(nameof(identifier));
            }

            using (var session = this.OpenAsyncSession())
            {
                var match = await
                    session.Query<RavenAccessToken>()
                        .Customize(x => x.WaitForNonStaleResultsAsOfLastWrite())
                        .Where(x => x.Token == identifier)
                        .FirstOrDefaultAsync();

                session.Delete(match);
                await session.SaveChangesAsync();

                return true;
            }
        }

        /// <summary>Deletes the specified access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAccessToken(IAccessToken accessToken)
        {
            using (var session = this.OpenAsyncSession())
            {
                var match = await
                    session.Query<RavenAccessToken>()
                        .Customize(x => x.WaitForNonStaleResultsAsOfLastWrite())
                        .Where(x => x.Token == accessToken.Token)
                        .FirstOrDefaultAsync();

                session.Delete(match);
                await session.SaveChangesAsync();

                return true;
            }
        }

        /// <summary>Gets the specified refresh token.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns>The refresh token.</returns>
        public async Task<IRefreshToken> GetRefreshToken(object identifier)
        {
            if (identifier == null)
            {
                throw new ArgumentNullException(nameof(identifier));
            }

            using (var session = this.OpenAsyncSession())
            {
                return await
                    session.Query<RavenRefreshToken>()
                        .Customize(x => x.WaitForNonStaleResultsAsOfLastWrite())
                        .Where(x => x.Token == identifier)
                        .FirstOrDefaultAsync();
            }
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
            using (var session = this.OpenAsyncSession())
            {
                return
                    await
                    session.Query<RavenRefreshToken>()
                        .Customize(x => x.WaitForNonStaleResultsAsOfLastWrite())
                        .Where(x => x.ClientId == clientId && x.ValidTo > expires)
                        .ToListAsync();
            }
        }

        /// <summary>
        /// Gets all refresh tokens for the specified user that expires **after** the specified date. 
        /// </summary>
        /// <param name="subject">The subject.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The refresh tokens.</returns>
        public async Task<IEnumerable<IRefreshToken>> GetUserRefreshTokens(string subject, DateTimeOffset expires)
        {
            using (var session = this.OpenAsyncSession())
            {
                return await session.Query<RavenRefreshToken>().Customize(x => x.WaitForNonStaleResultsAsOfLastWrite()).Where(x => x.Subject == subject && x.ValidTo > expires).ToListAsync();
            }
        }

        /// <summary>Inserts the specified refresh token. Called when creating a refresh token.</summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>The inserted refresh token. <c>null</c> if the insertion was unsuccessful.</returns>
        public async Task<IRefreshToken> InsertRefreshToken(IRefreshToken refreshToken)
        {
            var token = new RavenRefreshToken(refreshToken);

            // Validate token
            if (!token.IsValid())
            {
                throw new ArgumentException($"The refresh token is invalid: {JsonConvert.SerializeObject(token)}", nameof(refreshToken));
            }

            using (var session = this.OpenAsyncSession())
            {
                await session.StoreAsync(token);
                await session.SaveChangesAsync();

                return token;
            }
        }

        /// <summary>
        /// Deletes the refresh tokens that expires before the specified expire date. Called when
        /// creating a refresh token to cleanup.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<int> DeleteRefreshTokens(DateTimeOffset expires)
        {
            using (var session = this.OpenAsyncSession())
            {
                var i = 0;
                var matches = await session.Query<RavenRefreshToken>().Customize(x => x.WaitForNonStaleResultsAsOfLastWrite()).Where(x => x.ValidTo <= expires).ToListAsync();

                foreach (var match in matches)
                {
                    session.Delete(match);
                    i++;
                }

                if (i > 0)
                {
                    await session.SaveChangesAsync();
                }

                return i;
            }
        }

        /// <summary>Deletes the refresh tokens belonging to the specified client, redirect uri and subject.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="subject">The subject.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<int> DeleteRefreshTokens(string clientId, string redirectUri, string subject)
        {
            using (var session = this.OpenAsyncSession())
            {
                var i = 0;
                var matches =
                    await
                    session.Query<RavenRefreshToken>()
                        .Customize(x => x.WaitForNonStaleResultsAsOfLastWrite())
                        .Where(x => x.ClientId == clientId && x.RedirectUri == redirectUri && x.Subject == subject)
                        .ToListAsync();

                foreach (var match in matches)
                {
                    session.Delete(match);
                    i++;
                }

                if (i > 0)
                {
                    await session.SaveChangesAsync();
                }

                return i;
            }
        }

        /// <summary>Deletes the specified refresh token.</summary>
        /// <param name="identifier">The identifier.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteRefreshToken(object identifier)
        {
            if (identifier == null)
            {
                throw new ArgumentNullException(nameof(identifier));
            }

            using (var session = this.OpenAsyncSession())
            {
                var match =
                    await
                    session.Query<RavenRefreshToken>()
                        .Customize(x => x.WaitForNonStaleResultsAsOfLastWrite())
                        .Where(x => x.Token == identifier)
                        .FirstOrDefaultAsync();

                session.Delete(match);
                await session.SaveChangesAsync();

                return true;
            }
        }

        /// <summary>
        /// Deletes the specified refresh token. Called when authenticating a refresh token to prevent re-
        /// use.
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteRefreshToken(IRefreshToken refreshToken)
        {
            using (var session = this.OpenAsyncSession())
            {
                var match = await
                    session.Query<RavenRefreshToken>()
                        .Customize(x => x.WaitForNonStaleResultsAsOfLastWrite())
                        .Where(x => x.Token == refreshToken.Token)
                        .FirstOrDefaultAsync();

                session.Delete(match);
                await session.SaveChangesAsync();

                return true;
            }
        }

        /// <summary>Deletes all access tokens, refresh tokens and authorization codes.</summary>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> Purge()
        {
            using (var session = this.OpenAsyncSession())
            {
                session.Advanced.DocumentStore.Conventions.DefaultQueryingConsistency = ConsistencyOptions.AlwaysWaitForNonStaleResultsAsOfLastWrite;

                try
                {
                    // If the Raven/DocumentsByEntityName index does not exist, no entities exist
                    if (session.Advanced.DocumentStore.DatabaseCommands.GetIndex("AuthorizationCodes/Ids") != null)
                    {
                        await session.Advanced.DocumentStore.DatabaseCommands.DeleteByIndex(
                            "AuthorizationCodes/Ids",
                            new IndexQuery()).WaitForCompletionAsync();
                    }

                    if (session.Advanced.DocumentStore.DatabaseCommands.GetIndex("AccessTokens/Ids") != null)
                    {
                        await session.Advanced.DocumentStore.DatabaseCommands.DeleteByIndex(
                            "AccessTokens/Ids",
                            new IndexQuery()).WaitForCompletionAsync();
                    }

                    if (session.Advanced.DocumentStore.DatabaseCommands.GetIndex("RefreshTokens/Ids") != null)
                    {
                        await session.Advanced.DocumentStore.DatabaseCommands.DeleteByIndex(
                            "RefreshTokens/Ids",
                            new IndexQuery()).WaitForCompletionAsync();
                    }
                }
                catch (Exception ex)
                {
                    this.Configuration.Log.Error(ex);

                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Opens a document session.
        /// </summary>
        /// <returns>The document session.</returns>
        protected virtual IAsyncDocumentSession OpenAsyncSession()
        {
            if (this.Configuration.DocumentStore.GetType().Name == "EmbeddableDocumentStore")
            {
                return this.Configuration.DocumentStore.OpenAsyncSession();
            }

            return this.Configuration.DocumentStore.OpenAsyncSession("Sentinel.OAuth");
        }
    }
}