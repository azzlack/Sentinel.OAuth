namespace Sentinel.OAuth.Implementation.Managers
{
    using Common.Logging;
    using Newtonsoft.Json;
    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Core.Managers;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Models.Identity;
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Claims;
    using System.Linq;
    using System.Threading.Tasks;

    /// <summary>A universal token manager. Takes care of processing the tokens without caring where and how they are stored.</summary>
    public class TokenManager : BaseTokenManager
    {
        /// <summary>The logger.</summary>
        private readonly ILog logger;

        /// <summary>Initializes a new instance of the TokenManager class.</summary>
        /// <exception cref="ArgumentNullException">Thrown when one or more required arguments are null.</exception>
        /// <param name="logger">The logger.</param>
        /// <param name="principalProvider">The principal provider.</param>
        /// <param name="tokenProvider">The token provider.</param>
        /// <param name="tokenRepository">The token repository.</param>
        public TokenManager(ILog logger, IPrincipalProvider principalProvider, ITokenProvider tokenProvider, ITokenRepository tokenRepository)
            : base(principalProvider, tokenProvider, tokenRepository)
        {
            if (logger == null)
            {
                throw new ArgumentNullException(nameof(logger));
            }

            this.logger = logger;
        }

        /// <summary>Authenticates the authorization code.</summary>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns>The client principal.</returns>
        public override async Task<ISentinelPrincipal> AuthenticateAuthorizationCodeAsync(string redirectUri, string authorizationCode)
        {
            this.logger.DebugFormat("Authenticating authorization code '{0}' for redirect uri '{1}'", authorizationCode, redirectUri);

            var relevantCodes = await this.TokenRepository.GetAuthorizationCodes(redirectUri, DateTimeOffset.UtcNow);

            var validationResult = await this.TokenProvider.ValidateAuthorizationCode(relevantCodes, authorizationCode);

            if (validationResult.IsValid)
            {
                this.logger.Debug("Authorization code is valid");

                // Delete used authorization code
                var deleteResult = await this.TokenRepository.DeleteAuthorizationCode(validationResult.Entity);

                if (!deleteResult)
                {
                    this.logger.Error($"Unable to delete used authorization code: {JsonConvert.SerializeObject(validationResult)}");
                }

                // Set correct authentication method and return new principal
                return this.PrincipalProvider.Create(
                    AuthenticationType.OAuth,
                    validationResult.Principal.Identity.Claims.ToArray());
            }

            this.logger.Warn("Authorization code is not valid");

            return this.PrincipalProvider.Anonymous;
        }

        /// <summary>Authenticates the access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The user principal.</returns>
        public override async Task<ISentinelPrincipal> AuthenticateAccessTokenAsync(string accessToken)
        {
            this.logger.Debug("Authenticating access token");

            var relevantTokens = await this.TokenRepository.GetAccessTokens(DateTimeOffset.UtcNow);

            var validationResult = await this.TokenProvider.ValidateAccessToken(relevantTokens, accessToken);

            if (validationResult.IsValid)
            {
                this.logger.DebugFormat(
                    "Access token is valid. It belongs to the user '{0}', client '{1}' and redirect uri '{2}'",
                    validationResult.Entity.Subject,
                    validationResult.Entity.ClientId,
                    validationResult.Entity.RedirectUri);

                return this.PrincipalProvider.Create(AuthenticationType.OAuth, validationResult.Principal.Identity.Claims.ToArray());
            }

            this.logger.WarnFormat("Access token '{0}' is not valid", accessToken);

            return this.PrincipalProvider.Anonymous;
        }

        /// <summary>Authenticates the refresh token.</summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="refreshToken">The refresh token.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <returns>The user principal.</returns>
        public override async Task<ISentinelPrincipal> AuthenticateRefreshTokenAsync(string clientId, string redirectUri, string refreshToken)
        {
            this.logger.DebugFormat("Authenticating refresh token for client '{0}' and redirect uri '{1}'", clientId, redirectUri);

            var relevantTokens = await this.TokenRepository.GetRefreshTokens(clientId, redirectUri, DateTimeOffset.UtcNow);

            var validationResult = await this.TokenProvider.ValidateRefreshToken(relevantTokens, refreshToken);

            if (validationResult.IsValid)
            {
                if (validationResult.Entity.ClientId == clientId && validationResult.Entity.RedirectUri == redirectUri)
                {
                    this.logger.DebugFormat("Refresh token is valid. It belongs to the user '{0}', client '{1}' and redirect uri '{2}'", validationResult.Entity.Subject, validationResult.Entity.ClientId, validationResult.Entity.RedirectUri);

                    // Delete refresh token to prevent it being used again
                    var deleteResult = await this.TokenRepository.DeleteRefreshToken(validationResult.Entity);

                    if (!deleteResult)
                    {
                        this.logger.Error($"Unable to delete used refresh token: {JsonConvert.SerializeObject(validationResult.Entity)}");
                    }

                    var principal = this.PrincipalProvider.Create(
                        AuthenticationType.OAuth,
                        new SentinelClaim(ClaimType.Client, validationResult.Entity.ClientId),
                        new SentinelClaim(ClaimTypes.Name, validationResult.Entity.Subject),
                        new SentinelClaim(ClaimType.RedirectUri, validationResult.Entity.RedirectUri));

                    if (validationResult.Entity.Scope != null)
                    {
                        principal.Identity.AddClaim(ClaimType.Scope, string.Join(" ", validationResult.Entity.Scope));
                    }

                    return principal;
                }
            }

            this.logger.WarnFormat("Refresh token '{0}' is not valid", refreshToken);

            return this.PrincipalProvider.Anonymous;
        }

        /// <summary>Generates an authorization code for the specified client.</summary>
        /// <exception cref="ArgumentException">
        /// Thrown when one or more arguments have unsupported or illegal values.
        /// </exception>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="expire">The expire time.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="scope">The scope.</param>
        /// <returns>An authorization code.</returns>
        public override async Task<TokenCreationResult<IAuthorizationCode>> CreateAuthorizationCodeAsync(ISentinelPrincipal userPrincipal, TimeSpan expire, string redirectUri, IEnumerable<string> scope)
        {
            if (!userPrincipal.Identity.IsAuthenticated)
            {
                this.logger.Error("The specified user is not authenticated");

                return null;
            }

            var client = userPrincipal.Identity.Claims.FirstOrDefault(x => x.Type == ClaimType.Client);

            if (client == null || string.IsNullOrEmpty(client.Value))
            {
                throw new ArgumentException("The specified principal does not have a valid client identifier", nameof(userPrincipal));
            }

            // Delete all expired authorization codes
            await this.TokenRepository.DeleteAuthorizationCodes(DateTimeOffset.UtcNow);

            // Add scope claims
            if (scope != null)
            {
                userPrincipal.Identity.AddClaim(scope.Select(x => new SentinelClaim(ClaimType.Scope, x)).ToArray());
            }

            // Create and store authorization code for future use
            this.logger.DebugFormat("Creating authorization code for client '{0}', redirect uri '{1}' and user '{2}'", client, redirectUri, userPrincipal.Identity.Name);

            var createResult = await this.TokenProvider.CreateAuthorizationCode(
                client.Value,
                redirectUri,
                userPrincipal,
                scope,
                DateTimeOffset.UtcNow.Add(expire));

            // Add authorization code to database
            var insertResult = await this.TokenRepository.InsertAuthorizationCode(createResult.Entity);

            if (insertResult != null)
            {
                this.logger.Debug("Successfully created and stored authorization code");

                return new TokenCreationResult<IAuthorizationCode>(createResult.Token, insertResult);
            }

            this.logger.Error("Unable to create and/or store authorization code");

            return null;
        }

        /// <summary>Creates an access token.</summary>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="expire">The expire time.</param>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="scope">The scope.</param>
        /// <returns>An access token.</returns>
        public override async Task<TokenCreationResult<IAccessToken>> CreateAccessTokenAsync(ISentinelPrincipal userPrincipal, TimeSpan expire, string clientId, string redirectUri, IEnumerable<string> scope)
        {
            if (!userPrincipal.Identity.IsAuthenticated)
            {
                this.logger.Error("The specified principal is not authenticated");

                return null;
            }

            // Delete all expired access tokens
            await this.TokenRepository.DeleteAccessTokens(DateTimeOffset.UtcNow);

            // Add scope claims, but skip duplicates. (If the flow is authorization_code, the scopes might have been populated from before
            if (scope != null)
            {
                userPrincipal.Identity.AddClaim(scope.Where(x => !userPrincipal.Identity.HasClaim(ClaimType.Scope, x)).Select(x => new SentinelClaim(ClaimType.Scope, x)).ToArray());
            }

            this.logger.DebugFormat("Creating access token for client '{0}', redirect uri '{1}' and user '{2}'", clientId, redirectUri, userPrincipal.Identity.Name);

            var createResult = await this.TokenProvider.CreateAccessToken(
                clientId,
                redirectUri,
                userPrincipal,
                scope,
                DateTimeOffset.UtcNow.Add(expire));

            // Add access token to database
            var insertResult = await this.TokenRepository.InsertAccessToken(createResult.Entity);

            if (insertResult != null)
            {
                this.logger.Debug("Successfully created and stored access token");

                return new TokenCreationResult<IAccessToken>(createResult.Token, insertResult);
            }

            this.logger.Error("Unable to create and/or store access token");

            return null;
        }

        /// <summary>Creates a refresh token.</summary>
        /// <param name="userPrincipal">The principal.</param>
        /// <param name="expire">The expire time.</param>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="scope">The scope.</param>
        /// <returns>A refresh token.</returns>
        public override async Task<TokenCreationResult<IRefreshToken>> CreateRefreshTokenAsync(ISentinelPrincipal userPrincipal, TimeSpan expire, string clientId, string redirectUri, IEnumerable<string> scope)
        {
            if (!userPrincipal.Identity.IsAuthenticated)
            {
                this.logger.Error("The specified principal is not authenticated");

                return null;
            }

            // Delete all expired refresh tokens
            await this.TokenRepository.DeleteRefreshTokens(DateTimeOffset.UtcNow);

            // Add scope claims
            if (scope != null)
            {
                userPrincipal.Identity.AddClaim(scope.Where(x => !userPrincipal.Identity.HasClaim(ClaimType.Scope, x)).Select(x => new SentinelClaim(ClaimType.Scope, x)).ToArray());
            }

            this.logger.DebugFormat("Creating refresh token for client '{0}', redirect uri '{1}' and user '{2}'", clientId, redirectUri, userPrincipal.Identity.Name);

            var createResult =
                await
                this.TokenProvider.CreateRefreshToken(
                    clientId,
                    redirectUri,
                    userPrincipal,
                    scope,
                    DateTimeOffset.UtcNow.Add(expire));

            // Add refresh token to database
            var insertResult = await this.TokenRepository.InsertRefreshToken(createResult.Entity);

            if (insertResult != null)
            {
                this.logger.Debug("Successfully created and stored refresh token");

                return new TokenCreationResult<IRefreshToken>(createResult.Token, insertResult);
            }

            this.logger.Error("Unable to create and/or store refresh token");

            return null;
        }
    }
}