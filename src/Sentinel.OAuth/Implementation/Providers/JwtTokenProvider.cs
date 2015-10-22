namespace Sentinel.OAuth.Implementation.Providers
{
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Core.Models.OAuth;
    using Sentinel.OAuth.Models.Providers;
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Protocols.WSTrust;
    using System.IdentityModel.Tokens;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;

    public class JwtTokenProvider : ITokenProvider
    {
        /// <summary>The token repository.</summary>
        private readonly ITokenRepository tokenRepository;

        /// <summary>The client repository.</summary>
        private readonly IClientRepository clientRepository;

        /// <summary>The configuration.</summary>
        private readonly JwtTokenProviderConfiguration configuration;

        /// <summary>The token handler.</summary>
        private readonly JwtSecurityTokenHandler tokenHandler;

        /// <summary>Initializes a new instance of the Sentinel.OAuth.Implementation.Providers.JwtTokenProvider class.</summary>
        /// <param name="configuration">The configuration.</param>
        /// <param name="tokenRepository">The token repository.</param>
        /// <param name="clientRepository">The client repository.</param>
        public JwtTokenProvider(JwtTokenProviderConfiguration configuration, ITokenRepository tokenRepository, IClientRepository clientRepository)
        {
            this.tokenRepository = tokenRepository;
            this.clientRepository = clientRepository;
            this.configuration = configuration;

            this.tokenHandler = new JwtSecurityTokenHandler();
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
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(userPrincipal.Identity),
                TokenIssuerName = this.configuration.Issuer,
                AppliesToAddress = redirectUri,
                Lifetime = new Lifetime(DateTime.UtcNow, expireTime.UtcDateTime),
                SigningCredentials = this.configuration.SigningCredentials
            };

            var token = this.tokenHandler.CreateToken(tokenDescriptor) as JwtSecurityToken;

            if (token == null)
            {
                throw new InvalidOperationException("The token handler failed to produce a valid token");
            }

            var ticket = this.tokenHandler.WriteToken(token);

            var authorizationCode = new AuthorizationCode()
            {
                ClientId = clientId,
                RedirectUri = redirectUri,
                Subject = userPrincipal.Identity.Name,
                Scope = scope,
                Code = ticket,
                Ticket = ticket,
                ValidTo = expireTime
            };

            return new TokenCreationResult<IAuthorizationCode>(ticket, authorizationCode);
        }

        /// <summary>Validates an authorization code.</summary>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="code">The code.</param>
        /// <returns>The access token if valid, <c>null</c> otherwise.</returns>
        public async Task<bool> ValidateAuthorizationCode(string code)
        {
            var clients = await this.clientRepository.GetClients();

            var validationParams = new TokenValidationParameters()
            {
                ValidAudiences = clients.Select(x => x.RedirectUri),
                IssuerSigningToken = this.configuration.SigningKey,
                ValidIssuer = this.configuration.Issuer
            };

            SecurityToken token;
            var principal = this.tokenHandler.ValidateToken(code, validationParams, out token);

            if (principal.Identity.IsAuthenticated)
            {
                return true;
            }

            return false;
        }

        /// <summary>Creates an access token.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="expireTime">The expire time.</param>
        /// <returns>An object containing the new access token entity and the hashed token.</returns>
        public Task<TokenCreationResult<IAccessToken>> CreateAccessToken(
            string clientId,
            string redirectUri,
            ISentinelPrincipal userPrincipal,
            IEnumerable<string> scope,
            DateTimeOffset expireTime)
        {
            throw new NotImplementedException();
        }

        /// <summary>Validates an access token.</summary>
        /// <param name="token">The token.</param>
        /// <returns>The access token if valid, <c>null</c> otherwise.</returns>
        public Task<bool> ValidateAccessToken(string token)
        {
            throw new NotImplementedException();
        }

        /// <summary>Creates an access token.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="expireTime">The expire time.</param>
        /// <returns>An object containing the new access token entity and the hashed token.</returns>
        public Task<TokenCreationResult<IRefreshToken>> CreateRefreshToken(
            string clientId,
            string redirectUri,
            ISentinelPrincipal userPrincipal,
            IEnumerable<string> scope,
            DateTimeOffset expireTime)
        {
            throw new NotImplementedException();
        }

        /// <summary>Validates an access token.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="token">The token.</param>
        /// <returns>The access token if valid, <c>null</c> otherwise.</returns>
        public Task<bool> ValidateRefreshToken(string token)
        {
            throw new NotImplementedException();
        }
    }
}