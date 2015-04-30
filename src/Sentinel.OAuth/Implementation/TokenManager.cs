namespace Sentinel.OAuth.Implementation
{
    using System;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Common.Logging;

    using Newtonsoft.Json;

    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Core.Models.Identity;
    using Sentinel.OAuth.Core.Models.OAuth;

    public class TokenManager : ITokenManager
    {
        /// <summary>The logger.</summary>
        private readonly ILog logger;

        /// <summary>The principal provider.</summary>
        private readonly IPrincipalProvider principalProvider;

        /// <summary>The crypto provider.</summary>
        private readonly ICryptoProvider cryptoProvider;

        /// <summary>
        ///     Initializes a new instance of the Sentinel.OAuth.Implementation.MemoryTokenManager class.
        /// </summary>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when one or more required arguments are null.
        /// </exception>
        /// <param name="logger">The logger.</param>
        /// <param name="principalProvider">The principal provider.</param>
        /// <param name="cryptoProvider">The crypto provider.</param>
        /// <param name="tokenRepository">The token repository.</param>
        public TokenManager(ILog logger, IPrincipalProvider principalProvider, ICryptoProvider cryptoProvider, ITokenRepository tokenRepository)
        {
            if (logger == null)
            {
                throw new ArgumentNullException("logger");
            }

            if (principalProvider == null)
            {
                throw new ArgumentNullException("principalProvider");
            }

            if (cryptoProvider == null)
            {
                throw new ArgumentNullException("cryptoProvider");
            }

            if (tokenRepository == null)
            {
                throw new ArgumentNullException("tokenRepository");
            }

            this.logger = logger;
            this.principalProvider = principalProvider;
            this.cryptoProvider = cryptoProvider;
            this.TokenRepository = tokenRepository;
        }

        /// <summary>The token repository.</summary>
        /// <value>The token repository.</value>
        public ITokenRepository TokenRepository { get; private set; }

        /// <summary>Authenticates the authorization code.</summary>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns>The client principal.</returns>
        public async Task<ClaimsPrincipal> AuthenticateAuthorizationCodeAsync(string redirectUri, string authorizationCode)
        {
            this.logger.DebugFormat("Authenticating authorization code '{0}' for redirect uri '{1}'", authorizationCode, redirectUri);

            var authorizationCodes = await this.TokenRepository.GetAuthorizationCodes(x => x.RedirectUri == redirectUri && x.ValidTo > DateTime.UtcNow);

            var entity = authorizationCodes.FirstOrDefault(x => this.cryptoProvider.ValidateHash(authorizationCode, x.Code));

            if (entity != null)
            {
                this.logger.DebugFormat("Authorization code is valid");

                // Delete used authorization code
                await this.TokenRepository.DeleteAuthorizationCode(entity);

                var storedPrincipal = this.principalProvider.Decrypt(entity.Ticket, authorizationCode);

                this.logger.DebugFormat("Client '{0}' was given the following claims from the IPrincipalFactory: '{1}'", storedPrincipal.Identity.Name, JsonConvert.SerializeObject(new JsonPrincipal(storedPrincipal).Claims));

                // Set correct authentication method and return new principal
                return this.principalProvider.Create(AuthenticationType.OAuth, storedPrincipal.Claims.ToArray());
            }

            this.logger.Warn("Authorization code is not valid");

            return this.principalProvider.Anonymous;
        }

        /// <summary>Authenticates the access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The user principal.</returns>
        public async Task<ClaimsPrincipal> AuthenticateAccessTokenAsync(string accessToken)
        {
            this.logger.DebugFormat("Authenticating access token");

            var accessTokens = await this.TokenRepository.GetAccessTokens(x => x.ValidTo > DateTime.UtcNow);

            var entity = accessTokens.FirstOrDefault(x => this.cryptoProvider.ValidateHash(accessToken, x.Token));

            if (entity != null)
            {
                this.logger.DebugFormat("Access token is valid. It belongs to the user '{0}', client '{1}' and redirect uri '{2}'", entity.Subject, entity.ClientId, entity.RedirectUri);

                var storedPrincipal = this.principalProvider.Decrypt(entity.Ticket, accessToken);

                return this.principalProvider.Create(AuthenticationType.OAuth, storedPrincipal.Claims.ToArray());
            }

            this.logger.WarnFormat("Access token '{0}' is not valid", accessToken);

            return this.principalProvider.Anonymous;
        }

        /// <summary>Authenticates the refresh token.</summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="refreshToken">The refresh token.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <returns>The user principal.</returns>
        public async Task<ClaimsPrincipal> AuthenticateRefreshTokenAsync(string clientId, string refreshToken, string redirectUri)
        {
            this.logger.DebugFormat("Authenticating refresh token for client '{0}' and redirect uri '{1}'", clientId, redirectUri);

            var refreshTokens =
                await
                this.TokenRepository.GetRefreshTokens(
                    x => x.RedirectUri == redirectUri && x.ValidTo > DateTime.UtcNow);

            var entity = refreshTokens.FirstOrDefault(x => this.cryptoProvider.ValidateHash(refreshToken, x.Token));

            if (entity != null)
            {
                this.logger.DebugFormat("Refresh token is valid. It belongs to the user '{0}', client '{1}' and redirect uri '{2}'", entity.Subject, entity.ClientId, entity.RedirectUri);

                // Delete refresh token to prevent it being used again
                await this.TokenRepository.DeleteRefreshToken(entity);

                var storedPrincipal = this.principalProvider.Decrypt(entity.Ticket, refreshToken);

                // TODO: Must get new claims from user database so any changes in permissions are updated

                this.logger.DebugFormat("Client '{0}' was given the following claims from the IPrincipalFactory: '{1}'", storedPrincipal.Identity.Name, JsonConvert.SerializeObject(new JsonPrincipal(storedPrincipal).Claims));

                return this.principalProvider.Create(AuthenticationType.OAuth, storedPrincipal.Claims.ToArray());
            }

            this.logger.WarnFormat("Refresh token '{0}' is not valid", refreshToken);

            return this.principalProvider.Anonymous;
        }

        /// <summary>Generates an authorization code for the specified client.</summary>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="expire">The expire time.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="scope">The scope.</param>
        /// <returns>An authorization code.</returns>
        public async Task<string> CreateAuthorizationCodeAsync(ClaimsPrincipal userPrincipal, TimeSpan expire, string redirectUri, string[] scope = null)
        {
            if (!userPrincipal.Identity.IsAuthenticated)
            {
                this.logger.ErrorFormat("The specified user is not authenticated");

                return string.Empty;
            }

            var client = userPrincipal.Claims.FirstOrDefault(x => x.Type == ClaimType.Client);

            if (client == null || string.IsNullOrEmpty(client.Value))
            {
                throw  new ArgumentException("The specified principal does not have a valid client identifier", "userPrincipal");
            }

            // Delete all authorization codes for the specified user, client id, redirect uri to prevent exploitation
            var existingCodes = await this.TokenRepository.GetAuthorizationCodes(x => x.ClientId == client.Value && x.Subject == userPrincipal.Identity.Name && x.RedirectUri == redirectUri);

            if (existingCodes != null)
            {
                foreach (var existingToken in existingCodes)
                {
                    await this.TokenRepository.DeleteAuthorizationCode(existingToken);
                }
            }

            var claims = userPrincipal.Claims.ToList();

            // Remove unnecessary claims from principal
            claims.RemoveAll(x => x.Type == ClaimType.AccessToken || x.Type == ClaimType.RefreshToken);

            // Add scope claims
            if (scope != null)
            {
                claims.AddRange(scope.Select(x => new Claim(ClaimType.Scope, x)));
            }

            // Create and store authorization code fur future use
            this.logger.DebugFormat("Creating authorization code for '{0}' and redirect uri '{1}'", userPrincipal.Identity.Name, redirectUri);

            string code;
            var hashedCode = this.cryptoProvider.CreateHash(out code, 256);

            var authorizationCode = new AuthorizationCode(hashedCode, DateTime.UtcNow.Add(expire))
                                        {
                                            ClientId = client.Value,
                                            Subject = userPrincipal.Identity.Name,
                                            Ticket = this.principalProvider.Encrypt(new ClaimsPrincipal(new ClaimsIdentity(claims)), code),
                                            RedirectUri = redirectUri,
                                            Scope = scope
                                        };

            // Add authorization code to database
            var result = await this.TokenRepository.InsertAuthorizationCode(authorizationCode);

            if (result != null)
            {
                return code;
            }

            return string.Empty;
        }

        /// <summary>Creates an access token.</summary>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="expire">The expire time.</param>
        /// <param name="clientId">.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <returns>An access token.</returns>
        public async Task<string> CreateAccessTokenAsync(ClaimsPrincipal userPrincipal, TimeSpan expire, string clientId, string redirectUri)
        {
            if (!userPrincipal.Identity.IsAuthenticated)
            {
                this.logger.ErrorFormat("The specified principal is not authenticated");

                return string.Empty;
            }

            // Delete all expired access tokens as well as access tokens for the specified client id, user and redirect uri to prevent exploitation
            var existingTokens =
                await
                this.TokenRepository.GetAccessTokens(
                    x =>
                    x.ValidTo < DateTime.UtcNow
                    || (x.ClientId == clientId && x.Subject == userPrincipal.Identity.Name && x.RedirectUri == redirectUri));

            if (existingTokens != null)
            {
                foreach (var existingToken in existingTokens)
                {
                    await this.TokenRepository.DeleteAccessToken(existingToken);
                }
            }

            var claims = userPrincipal.Claims.ToList();

            // Remove unnecessary claims from principal
            claims.RemoveAll(x => x.Type == ClaimType.AccessToken || x.Type == ClaimType.RefreshToken);

            // Create new access token
            string token;
            var hashedToken = this.cryptoProvider.CreateHash(out token, 2048);

            var accessToken = new AccessToken(hashedToken, DateTime.UtcNow.Add(expire))
                                    {
                                        ClientId = clientId,
                                        Subject = userPrincipal.Identity.Name,
                                        Ticket = this.principalProvider.Encrypt(new ClaimsPrincipal(new ClaimsIdentity(claims)), token),
                                        RedirectUri = redirectUri
                                    };

            // Add refresh token to database
            var result = await this.TokenRepository.InsertAccessToken(accessToken);

            if (result != null)
            {
                return token;
            }

            return string.Empty;
        }

        /// <summary>Creates a refresh token.</summary>
        /// <param name="userPrincipal">The principal.</param>
        /// <param name="expire">The expire time.</param>
        /// <param name="clientId">.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <returns>A refresh token.</returns>
        public async Task<string> CreateRefreshTokenAsync(ClaimsPrincipal userPrincipal, TimeSpan expire, string clientId, string redirectUri)
        {
            if (!userPrincipal.Identity.IsAuthenticated)
            {
                this.logger.ErrorFormat("The specified principal is not authenticated");

                return string.Empty;
            }

            // Delete all expired refresh tokens as well as refresh tokens for the specified client id, user and redirect uri to prevent exploitation
            var existingTokens =
                await
                this.TokenRepository.GetRefreshTokens(
                    x =>
                    x.ValidTo < DateTime.UtcNow
                    || (x.ClientId == clientId && x.Subject == userPrincipal.Identity.Name && x.RedirectUri == redirectUri));

            if (existingTokens != null)
            {
                foreach (var existingToken in existingTokens)
                {
                    await this.TokenRepository.DeleteRefreshToken(existingToken);
                }
            }

            var claims = userPrincipal.Claims.ToList();

            // Remove unnecessary claims from principal
            claims.RemoveAll(x => x.Type == ClaimType.AccessToken || x.Type == ClaimType.RefreshToken);

            // Create new refresh token
            string token;
            var hashedToken = this.cryptoProvider.CreateHash(out token, 2048);

            var refreshToken = new RefreshToken(hashedToken, DateTime.UtcNow.Add(expire))
                                    {
                                        ClientId = clientId,
                                        Subject = userPrincipal.Identity.Name,
                                        Ticket = this.principalProvider.Encrypt(new ClaimsPrincipal(new ClaimsIdentity(claims)), token),
                                        RedirectUri = redirectUri
                                    };

            // Add refresh token to database
            var result = await this.TokenRepository.InsertRefreshToken(refreshToken);

            if (result != null)
            {
                return token;
            }

            return string.Empty;
        }
    }
}