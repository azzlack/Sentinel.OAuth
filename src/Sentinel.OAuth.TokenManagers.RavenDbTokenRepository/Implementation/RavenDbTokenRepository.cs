namespace Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Implementation
{
    using Raven.Abstractions.Data;
    using Raven.Client;
    using Raven.Client.Linq;
    using Raven.Imports.Newtonsoft.Json;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models;
    using Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models.OAuth;
    using System;
    using System.Collections.Generic;
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
        protected RavenDbTokenRepositoryConfiguration Configuration { get; private set; }

        /// <summary>
        /// Gets all authorization codes that matches the specified redirect uri and expires after the
        /// specified date. Called when authenticating an authorization code.
        /// </summary>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The authorization codes.</returns>
        public async Task<IEnumerable<IAuthorizationCode>> GetAuthorizationCodes(string redirectUri, DateTime expires)
        {
            using (var session = this.OpenAsyncSession())
            {
                return await session.Query<RavenAuthorizationCode>().Customize(x => x.WaitForNonStaleResultsAsOfLastWrite()).Where(x => x.RedirectUri == redirectUri && x.ValidTo > expires).ToListAsync();
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

            using (var session = this.OpenAsyncSession())
            {
                await session.StoreAsync(code);
                await session.SaveChangesAsync();

                return authorizationCode;
            }
        }

        /// <summary>
        /// Deletes the authorization codes that expires before the specified expire date. Called when
        /// creating an authorization code to cleanup.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted codes.</returns>
        public async Task<int> DeleteAuthorizationCodes(DateTime expires)
        {
            using (var session = this.OpenAsyncSession())
            {
                var i = 0;
                var matches = await session.Query<RavenAuthorizationCode>().Customize(x => x.WaitForNonStaleResultsAsOfLastWrite()).Where(x => x.ValidTo < expires).ToListAsync();

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

        /// <summary>
        /// Deletes the specified authorization code. Called when authenticating an authorization code to
        /// prevent re-use.
        /// </summary>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAuthorizationCode(IAuthorizationCode authorizationCode)
        {
            var code = new RavenAuthorizationCode(authorizationCode);

            using (var session = this.OpenAsyncSession())
            {
                var match = await session.LoadAsync<RavenAuthorizationCode>(code.Id);

                session.Delete(match);
                await session.SaveChangesAsync();

                return true;
            }
        }

        /// <summary>
        /// Gets all access tokens that expires **after** the specified date. Called when authenticating
        /// an access token to limit the number of tokens to go through when validating the hash.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The access tokens.</returns>
        public async Task<IEnumerable<IAccessToken>> GetAccessTokens(DateTime expires)
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
        public async Task<IEnumerable<IAccessToken>> GetAccessTokens(string subject, DateTime expires)
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

                return accessToken;
            }
        }

        /// <summary>
        /// Deletes the access tokens that expires before the specified expire date. Called when creating
        /// an access token to cleanup.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<int> DeleteAccessTokens(DateTime expires)
        {
            using (var session = this.OpenAsyncSession())
            {
                var i = 0;
                var matches =
                    await
                    session.Query<RavenAccessToken>()
                        .Customize(x => x.WaitForNonStaleResultsAsOfLastWrite())
                        .Where(x => x.ValidTo < expires)
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
        /// <param name="accessToken">The access token.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteAccessToken(IAccessToken accessToken)
        {
            var token = new RavenAccessToken(accessToken);

            using (var session = this.OpenAsyncSession())
            {
                var match = await session.LoadAsync<RavenAccessToken>(token.Id);

                session.Delete(match);
                await session.SaveChangesAsync();

                return true;
            }
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
            using (var session = this.OpenAsyncSession())
            {
                return await session.Query<RavenRefreshToken>().Customize(x => x.WaitForNonStaleResultsAsOfLastWrite()).Where(x => x.ClientId == clientId && x.RedirectUri == redirectUri && x.ValidTo > expires).ToListAsync();
            }
        }

        /// <summary>Inserts the specified refresh token. Called when creating a refresh token.</summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>The inserted refresh token. <c>null</c> if the insertion was unsuccessful.</returns>
        public async Task<IRefreshToken> InsertRefreshToken(IRefreshToken refreshToken)
        {
            var token = new RavenRefreshToken(refreshToken);

            using (var session = this.OpenAsyncSession())
            {
                await session.StoreAsync(token);
                await session.SaveChangesAsync();

                return refreshToken;
            }
        }

        /// <summary>
        /// Deletes the refresh tokens that expires before the specified expire date. Called when
        /// creating a refresh token to cleanup.
        /// </summary>
        /// <param name="expires">The expire date.</param>
        /// <returns>The number of deleted tokens.</returns>
        public async Task<int> DeleteRefreshTokens(DateTime expires)
        {
            using (var session = this.OpenAsyncSession())
            {
                var i = 0;
                var matches = await session.Query<RavenRefreshToken>().Customize(x => x.WaitForNonStaleResultsAsOfLastWrite()).Where(x => x.ValidTo < expires).ToListAsync();

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

        /// <summary>
        /// Deletes the specified refresh token. Called when authenticating a refresh token to prevent re-
        /// use.
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns><c>True</c> if successful, <c>false</c> otherwise.</returns>
        public async Task<bool> DeleteRefreshToken(IRefreshToken refreshToken)
        {
            var token = new RavenRefreshToken(refreshToken);

            using (var session = this.OpenAsyncSession())
            {
                var match = await session.LoadAsync<RavenRefreshToken>(token.Id);

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
                try
                {
                    session.Advanced.DocumentStore.DatabaseCommands.DeleteByIndex(
                        "Raven/DocumentsByEntityName",
                        new IndexQuery { Query = "Tag:RavenAuthorizationCode" });
                    session.Advanced.DocumentStore.DatabaseCommands.DeleteByIndex(
                        "Raven/DocumentsByEntityName",
                        new IndexQuery { Query = "Tag:RavenAccessToken" });
                    session.Advanced.DocumentStore.DatabaseCommands.DeleteByIndex(
                        "Raven/DocumentsByEntityName",
                        new IndexQuery { Query = "Tag:RavenRefreshToken" });
                }
                catch (Exception)
                {
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