namespace Sentinel.OAuth.Core.Managers
{
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Interfaces.Factories;
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Interfaces.Repositories;

    public abstract class BaseTokenManager : ITokenManager
    {
        /// <summary>The token repository.</summary>
        private readonly ITokenRepository tokenRepository;

        /// <summary>Initializes a new instance of the BaseTokenManager class.</summary>
        /// <param name="principalProvider">The principal provider.</param>
        /// <param name="cryptoProvider">The crypto provider.</param>
        /// <param name="tokenFactory">The token factory.</param>
        /// <param name="tokenRepository">The token repository.</param>
        protected BaseTokenManager(IPrincipalProvider principalProvider, ICryptoProvider cryptoProvider, ITokenFactory tokenFactory, ITokenRepository tokenRepository)
        {
            this.CryptoProvider = cryptoProvider;
            this.PrincipalProvider = principalProvider;
            this.TokenFactory = tokenFactory;
            this.tokenRepository = tokenRepository;
        }

        /// <summary>Gets the token repository.</summary>
        /// <value>The token repository.</value>
        public ITokenRepository TokenRepository
        {
            get
            {
                return this.tokenRepository;
            }
        }

        /// <summary>Gets the principal provider.</summary>
        /// <value>The principal provider.</value>
        protected IPrincipalProvider PrincipalProvider { get; private set; }

        /// <summary>Gets the crypto provider.</summary>
        /// <value>The crypto provider.</value>
        protected ICryptoProvider CryptoProvider { get; private set; }

        /// <summary>Gets the token factory.</summary>
        /// <value>The token factory.</value>
        protected ITokenFactory TokenFactory { get; private set; }

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