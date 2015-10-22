namespace Sentinel.OAuth.Core.Managers
{
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    public abstract class BaseTokenManager : ITokenManager
    {
        /// <summary>The principal provider.</summary>
        private readonly IPrincipalProvider principalProvider;

        /// <summary>The token provider.</summary>
        private readonly ITokenProvider tokenProvider;

        /// <summary>The token repository.</summary>
        private readonly ITokenRepository tokenRepository;

        /// <summary>The client repository.</summary>
        private readonly IClientRepository clientRepository;


        /// <summary>Initializes a new instance of the BaseTokenManager class.</summary>
        /// <param name="principalProvider">The principal provider.</param>
        /// <param name="tokenProvider">The token provider.</param>
        /// <param name="tokenRepository">The token repository.</param>
        /// <param name="clientRepository">The client repository.</param>
        protected BaseTokenManager(IPrincipalProvider principalProvider, ITokenProvider tokenProvider, ITokenRepository tokenRepository, IClientRepository clientRepository)
        {
            this.principalProvider = principalProvider;
            this.tokenProvider = tokenProvider;
            this.tokenRepository = tokenRepository;
            this.clientRepository = clientRepository;
        }

        /// <summary>Authenticates the authorization code.</summary>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="authorizationCode">The authorization code.</param>
        /// <returns>The user principal.</returns>
        public abstract Task<ISentinelPrincipal> AuthenticateAuthorizationCodeAsync(string redirectUri, string authorizationCode);

        /// <summary>Authenticates the access token.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The user principal.</returns>
        public abstract Task<ISentinelPrincipal> AuthenticateAccessTokenAsync(string accessToken);

        /// <summary>Authenticates the refresh token.</summary>
        /// <param name="clientId">The client id.</param>
        /// <param name="refreshToken">The refresh token.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <returns>The user principal.</returns>
        public abstract Task<ISentinelPrincipal> AuthenticateRefreshTokenAsync(string clientId, string refreshToken, string redirectUri);

        /// <summary>Generates an authorization code for the specified client.</summary>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="expire">The expire time.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="scope">The scope.</param>
        /// <returns>An authorization code.</returns>
        public abstract Task<string> CreateAuthorizationCodeAsync(ISentinelPrincipal userPrincipal, TimeSpan expire, string redirectUri, IEnumerable<string> scope);

        /// <summary>Creates an access token.</summary>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="expire">The expire time.</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="scope">The scope.</param>
        /// <returns>An access token.</returns>
        public abstract Task<string> CreateAccessTokenAsync(ISentinelPrincipal userPrincipal, TimeSpan expire, string clientId, string redirectUri, IEnumerable<string> scope);

        /// <summary>Creates a refresh token.</summary>
        /// <param name="userPrincipal">The principal.</param>
        /// <param name="expire">The expire time.</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="scope">The scope.</param>
        /// <returns>A refresh token.</returns>
        public abstract Task<string> CreateRefreshTokenAsync(ISentinelPrincipal userPrincipal, TimeSpan expire, string clientId, string redirectUri, IEnumerable<string> scope);
    }
}