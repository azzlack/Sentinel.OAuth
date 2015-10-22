namespace Sentinel.OAuth.Implementation.Providers
{
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Core.Models.OAuth;
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    public class SentinelTokenProvider : ITokenProvider
    {
        /// <summary>The crypto provider.</summary>
        private readonly ICryptoProvider cryptoProvider;

        /// <summary>The principal provider.</summary>
        private readonly IPrincipalProvider principalProvider;

        /// <summary>Initializes a new instance of the Sentinel.OAuth.Implementation.Providers.SentinelTokenProvider class.</summary>
        /// <param name="cryptoProvider">The crypto provider.</param>
        /// <param name="principalProvider">The principal provider.</param>
        public SentinelTokenProvider(ICryptoProvider cryptoProvider, IPrincipalProvider principalProvider)
        {
            this.cryptoProvider = cryptoProvider;
            this.principalProvider = principalProvider;
        }

        /// <summary>Creates an authorization code.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="expireTime">The expire time.</param>
        /// <returns>An object containing the new access token entity and the hashed token.</returns>
        public async Task<TokenCreationResult<IAuthorizationCode>> CreateAuthorizationCode(
            string clientId,
            string redirectUri,
            ISentinelPrincipal userPrincipal,
            IEnumerable<string> scope,
            DateTimeOffset expireTime)
        {
            string code;
            var hashedCode = this.cryptoProvider.CreateHash(out code, 256);

            var authorizationCode = new AuthorizationCode()
            {
                ClientId = clientId,
                RedirectUri = redirectUri,
                Subject = userPrincipal.Identity.Name,
                Scope = scope,
                Code = hashedCode,
                Ticket = this.principalProvider.Encrypt(userPrincipal, code),
                ValidTo = expireTime
            };

            return new TokenCreationResult<IAuthorizationCode>(code, authorizationCode);
        }

        /// <summary>Validates an authorization code.</summary>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="code">The code.</param>
        /// <returns>The access token if valid, <c>null</c> otherwise.</returns>
        public async Task<bool> ValidateAuthorizationCode(string code)
        {
            return true;
        }

        /// <summary>Creates an access token.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">URI of the redirect.</param>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="expireTime">The expire time.</param>
        /// <returns>The new access token.</returns>
        public async Task<TokenCreationResult<IAccessToken>> CreateAccessToken(
            string clientId,
            string redirectUri,
            ISentinelPrincipal userPrincipal,
            IEnumerable<string> scope,
            DateTimeOffset expireTime)
        {
            string token;
            var hashedToken = this.cryptoProvider.CreateHash(out token, 2048);

            var accessToken = new AccessToken()
            {
                ClientId = clientId,
                RedirectUri = redirectUri,
                Subject = userPrincipal.Identity.Name,
                Scope = scope,
                Token = hashedToken,
                Ticket = this.principalProvider.Encrypt(userPrincipal, token),
                ValidTo = expireTime
            };

            return new TokenCreationResult<IAccessToken>(token, accessToken);
        }

        /// <summary>Validates an access token.</summary>
        /// <param name="token">The token.</param>
        /// <returns>The access token if valid, <c>null</c> otherwise.</returns>
        public async Task<bool> ValidateAccessToken(string token)
        {
            return true;
        }

        /// <summary>Creates an access token.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="expireTime">The expire time.</param>
        /// <returns>An object containing the new access token entity and the hashed token.</returns>
        public async Task<TokenCreationResult<IRefreshToken>> CreateRefreshToken(
            string clientId,
            string redirectUri,
            ISentinelPrincipal userPrincipal,
            IEnumerable<string> scope,
            DateTimeOffset expireTime)
        {
            string token;
            var hashedToken = this.cryptoProvider.CreateHash(out token, 2048);

            var refreshToken = new RefreshToken()
            {
                ClientId = clientId,
                RedirectUri = redirectUri,
                Subject = userPrincipal.Identity.Name,
                Scope = scope,
                Token = hashedToken,
                ValidTo = expireTime
            };

            return new TokenCreationResult<IRefreshToken>(token, refreshToken);
        }

        /// <summary>Validates an access token.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="token">The token.</param>
        /// <returns>The access token if valid, <c>null</c> otherwise.</returns>
        public async Task<bool> ValidateRefreshToken(string token)
        {
            return true;
        }
    }
}