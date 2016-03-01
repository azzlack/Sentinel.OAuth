namespace Sentinel.OAuth.Core.Managers
{
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models;

    public abstract class BaseTokenManager : ITokenManager
    {
        /// <summary>Initializes a new instance of the BaseTokenManager class.</summary>
        /// <param name="principalProvider">The principal provider.</param>
        /// <param name="tokenProvider">The token provider.</param>
        /// <param name="tokenRepository">The token repository.</param>
        /// <param name="clientRepository">The client repository.</param>
        protected BaseTokenManager(IPrincipalProvider principalProvider, ITokenProvider tokenProvider, ITokenRepository tokenRepository)
        {
            this.PrincipalProvider = principalProvider;
            this.TokenProvider = tokenProvider;
            this.TokenRepository = tokenRepository;
        }

        /// <summary>Gets the principal provider.</summary>
        /// <value>The principal provider.</value>
        protected IPrincipalProvider PrincipalProvider { get; }

        /// <summary>Gets the token provider.</summary>
        /// <value>The token provider.</value>
        protected ITokenProvider TokenProvider { get; }

        /// <summary>Gets the token repository.</summary>
        /// <value>The token repository.</value>
        protected ITokenRepository TokenRepository { get; }

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
        /// <returns>The user principal.</returns>
        public abstract Task<ISentinelPrincipal> AuthenticateRefreshTokenAsync(string clientId, string refreshToken);

        /// <summary>Generates an authorization code for the specified client.</summary>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="expire">The expire time.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="scope">The scope.</param>
        /// <returns>The token creation result.</returns>
        public abstract Task<TokenCreationResult<IAuthorizationCode>> CreateAuthorizationCodeAsync(ISentinelPrincipal userPrincipal, TimeSpan expire, string redirectUri, IEnumerable<string> scope);

        /// <summary>Creates an access token.</summary>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="expire">The expire time.</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="scope">The scope.</param>
        /// <returns>The token creation result.</returns>
        public abstract Task<TokenCreationResult<IAccessToken>> CreateAccessTokenAsync(ISentinelPrincipal userPrincipal, TimeSpan expire, string clientId, string redirectUri, IEnumerable<string> scope);

        /// <summary>Creates a refresh token.</summary>
        /// <param name="userPrincipal">The principal.</param>
        /// <param name="expire">The expire time.</param>
        /// <param name="clientId">The client id.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="scope">The scope.</param>
        /// <returns>The token creation result.</returns>
        public abstract Task<TokenCreationResult<IRefreshToken>> CreateRefreshTokenAsync(ISentinelPrincipal userPrincipal, TimeSpan expire, string clientId, string redirectUri, IEnumerable<string> scope);
    }
}