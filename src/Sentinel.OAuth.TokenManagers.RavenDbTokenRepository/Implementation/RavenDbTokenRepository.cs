namespace Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Implementation
{
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    using Raven.Client;
    using Raven.Client.Linq;

    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Models.OAuth;
    using Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models;

    /// <summary>A token repository using RavenDB for storage.</summary>
    public class RavenDbTokenRepository : ITokenRepository
    {
        /// <summary>The configuration.</summary>
        private readonly RavenDbTokenRepositoryConfiguration configuration;

        /// <summary>
        /// Initializes a new instance of the
        /// Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Implementation.RavenDbTokenRepository
        /// class.
        /// </summary>
        /// <param name="configuration">The configuration.</param>
        public RavenDbTokenRepository(RavenDbTokenRepositoryConfiguration configuration)
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
            using (var session = this.OpenAsyncSession())
            {
                return await session.Query<AuthorizationCode>().Where(x => x.RedirectUri == redirectUri && x.ValidTo > expires).Customize(x => x.WaitForNonStaleResultsAsOfLastWrite()).ToListAsync();
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
            using (var session = this.OpenAsyncSession())
            {
                await session.StoreAsync(authorizationCode);
                await session.SaveChangesAsync();

                return authorizationCode;
            }
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
            using (var session = this.OpenAsyncSession())
            {
                var i = 0;
                var matches = await session.Query<AuthorizationCode>().Customize(x => x.WaitForNonStaleResultsAsOfLastWrite()).Where(x => x.ClientId == clientId && x.RedirectUri == redirectUri && x.Subject == userId).ToListAsync();

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
                var matches = await session.Query<AuthorizationCode>().Customize(x => x.WaitForNonStaleResultsAsOfLastWrite()).Where(x => x.ValidTo < expires).ToListAsync();

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
            var code = (AuthorizationCode)authorizationCode;

            using (var session = this.OpenAsyncSession())
            {
                var match = await session.LoadAsync<AuthorizationCode>("AuthorizationCodes/" + code.Id);

                if (match != null)
                {
                    session.Delete(match);
                    await session.SaveChangesAsync();

                    return true;
                }
            }

            return false;
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
                return await session.Query<AccessToken>().Where(x => x.ValidTo > expires).Customize(x => x.WaitForNonStaleResultsAsOfLastWrite()).ToListAsync();
            }
        }

        /// <summary>Inserts the specified access token. Called when creating an access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The inserted access token. <c>null</c> if the insertion was unsuccessful.</returns>
        public async Task<IAccessToken> InsertAccessToken(IAccessToken accessToken)
        {
            using (var session = this.OpenAsyncSession())
            {
                await session.StoreAsync(accessToken);
                await session.SaveChangesAsync();

                return accessToken;
            }
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
            using (var session = this.OpenAsyncSession())
            {
                var i = 0;
                var matches = await session.Query<AccessToken>().Customize(x => x.WaitForNonStaleResultsAsOfLastWrite()).Where(x => x.ClientId == clientId && x.RedirectUri == redirectUri && x.Subject == userId).ToListAsync();

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
                var matches = await session.Query<AccessToken>().Customize(x => x.WaitForNonStaleResultsAsOfLastWrite()).Where(x => x.ValidTo < expires).ToListAsync();

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
        /// Gets all refresh tokens that matches the specified redirect uri and expires after the
        /// specified date. Called when authentication a refresh token to limit the number of tokens to
        /// go through when validating the hash.
        /// </summary>
        /// <param name="redirectUri">The redirect uri.</param>
        /// <param name="expires">The expire date.</param>
        /// <returns>The refresh tokens.</returns>
        public async Task<IEnumerable<IRefreshToken>> GetRefreshTokens(string redirectUri, DateTime expires)
        {
            using (var session = this.OpenAsyncSession())
            {
                return await session.Query<RefreshToken>().Where(x => x.ValidTo > expires).Customize(x => x.WaitForNonStaleResultsAsOfLastWrite()).ToListAsync();
            }
        }

        /// <summary>Inserts the specified refresh token. Called when creating a refresh token.</summary>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>The inserted refresh token. <c>null</c> if the insertion was unsuccessful.</returns>
        public async Task<IRefreshToken> InsertRefreshToken(IRefreshToken refreshToken)
        {
            using (var session = this.OpenAsyncSession())
            {
                await session.StoreAsync(refreshToken);
                await session.SaveChangesAsync();

                return refreshToken;
            }
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
            using (var session = this.OpenAsyncSession())
            {
                var i = 0;
                var matches = await session.Query<RefreshToken>().Customize(x => x.WaitForNonStaleResultsAsOfLastWrite()).Where(x => x.ClientId == clientId && x.RedirectUri == redirectUri && x.Subject == userId).ToListAsync();

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
                var matches = await session.Query<RefreshToken>().Customize(x => x.WaitForNonStaleResultsAsOfLastWrite()).Where(x => x.ValidTo < expires).ToListAsync();

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
            var token = (RefreshToken)refreshToken;

            using (var session = this.OpenAsyncSession())
            {
                var match = await session.LoadAsync<RefreshToken>("RefreshTokens/" + token.Id);

                if (match != null)
                {
                    session.Delete(match);
                    await session.SaveChangesAsync();

                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Opens a document session.
        /// </summary>
        /// <returns>The document session.</returns>
        public IAsyncDocumentSession OpenAsyncSession()
        {
            if (this.configuration.DocumentStore.GetType().Name == "EmbeddableDocumentStore")
            {
                return this.configuration.DocumentStore.OpenAsyncSession();
            }

            return this.configuration.DocumentStore.OpenAsyncSession("Sentinel.OAuth");
        }
    }
}