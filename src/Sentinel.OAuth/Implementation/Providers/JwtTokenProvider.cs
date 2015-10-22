namespace Sentinel.OAuth.Implementation.Providers
{
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Core.Models.OAuth;
    using Sentinel.OAuth.Models.Identity;
    using Sentinel.OAuth.Models.Providers;
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Protocols.WSTrust;
    using System.IdentityModel.Tokens;
    using System.Linq;
    using System.Security.Claims;
    using System.Text;
    using System.Threading.Tasks;

    public class JwtTokenProvider : ITokenProvider
    {
        /// <summary>The configuration.</summary>
        private readonly JwtTokenProviderConfiguration configuration;

        /// <summary>The token handler.</summary>
        private readonly JwtSecurityTokenHandler tokenHandler;

        /// <summary>Initializes a new instance of the Sentinel.OAuth.Implementation.Providers.JwtTokenProvider class.</summary>
        /// <param name="configuration">The configuration.</param>
        /// <param name="tokenRepository">The token repository.</param>
        /// <param name="clientRepository">The client repository.</param>
        public JwtTokenProvider(JwtTokenProviderConfiguration configuration)
        {
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
                Code = token.RawSignature,
                Ticket = ticket,
                ValidTo = expireTime
            };

            return new TokenCreationResult<IAuthorizationCode>(Convert.ToBase64String(Encoding.UTF8.GetBytes(token.RawSignature)), authorizationCode);
        }

        /// <summary>Validates an authorization code.</summary>
        /// <param name="authorizationCodes">The authorization codes to validate against.</param>
        /// <param name="code">The code.</param>
        /// <returns>The access token if valid, <c>null</c> otherwise.</returns>
        public async Task<TokenValidationResult<IAuthorizationCode>> ValidateAuthorizationCode(IEnumerable<IAuthorizationCode> authorizationCodes, string code)
        {
            var entity = authorizationCodes.FirstOrDefault(x => x.Code == Encoding.UTF8.GetString(Convert.FromBase64String(code)));

            if (entity != null)
            {
                var validationParams = new TokenValidationParameters()
                {
                    ValidAudience = entity.RedirectUri,
                    IssuerSigningToken = this.configuration.SigningKey,
                    ValidIssuer = this.configuration.Issuer
                };

                SecurityToken st;
                var principal = this.tokenHandler.ValidateToken(entity.Ticket, validationParams, out st);

                if (principal.Identity.IsAuthenticated)
                {
                    return new TokenValidationResult<IAuthorizationCode>(new SentinelPrincipal(principal), entity);
                }
            }

            return new TokenValidationResult<IAuthorizationCode>(SentinelPrincipal.Anonymous, null);
        }

        /// <summary>Creates an access token.</summary>
        /// <param name="clientId">Identifier for the client.</param>
        /// <param name="redirectUri">The redirect URI.</param>
        /// <param name="userPrincipal">The user principal.</param>
        /// <param name="scope">The scope.</param>
        /// <param name="expireTime">The expire time.</param>
        /// <returns>An object containing the new access token entity and the hashed token.</returns>
        public async Task<TokenCreationResult<IAccessToken>> CreateAccessToken(
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

            var accessToken = new AccessToken()
            {
                ClientId = clientId,
                RedirectUri = redirectUri,
                Subject = userPrincipal.Identity.Name,
                Scope = scope,
                Token = ticket,
                Ticket = ticket,
                ValidTo = expireTime
            };

            return new TokenCreationResult<IAccessToken>(ticket, accessToken);
        }

        /// <summary>Validates the access token.</summary>
        /// <param name="accessTokens">The access tokens to validate against.</param>
        /// <param name="token">The token.</param>
        /// <returns>The token principal if valid, <c>null</c> otherwise.</returns>
        public async Task<TokenValidationResult<IAccessToken>> ValidateAccessToken(IEnumerable<IAccessToken> accessTokens, string token)
        {
            var entity = accessTokens.FirstOrDefault(x => x.Token == token);

            if (entity != null)
            {
                var validationParams = new TokenValidationParameters()
                {
                    ValidAudience = entity.RedirectUri,
                    IssuerSigningToken = this.configuration.SigningKey,
                    ValidIssuer = this.configuration.Issuer
                };

                SecurityToken st;
                var principal = this.tokenHandler.ValidateToken(token, validationParams, out st);

                if (principal.Identity.IsAuthenticated)
                {
                    return new TokenValidationResult<IAccessToken>(new SentinelPrincipal(principal), entity);
                }
            }

            return new TokenValidationResult<IAccessToken>(SentinelPrincipal.Anonymous, null);
        }

        /// <summary>Creates a refresh token.</summary>
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

            var refreshToken = new RefreshToken()
            {
                ClientId = clientId,
                RedirectUri = redirectUri,
                Subject = userPrincipal.Identity.Name,
                Scope = scope,
                Token = ticket,
                ValidTo = expireTime
            };

            return new TokenCreationResult<IRefreshToken>(Convert.ToBase64String(Encoding.UTF8.GetBytes(ticket)), refreshToken);
        }

        /// <summary>Validates the refresh token.</summary>
        /// <param name="refreshTokens">The refresh tokens to validate against.</param>
        /// <param name="token">The token.</param>
        /// <returns>The token principal if valid, <c>null</c> otherwise.</returns>
        public async Task<TokenValidationResult<IRefreshToken>> ValidateRefreshToken(IEnumerable<IRefreshToken> refreshTokens, string token)
        {
            var id = Encoding.UTF8.GetString(Convert.FromBase64String(token));

            var entity = refreshTokens.FirstOrDefault(x => x.Token == id);

            if (entity != null)
            {
                var validationParams = new TokenValidationParameters()
                {
                    ValidAudience = entity.RedirectUri,
                    IssuerSigningToken = this.configuration.SigningKey,
                    ValidIssuer = this.configuration.Issuer
                };

                SecurityToken st;
                var principal = this.tokenHandler.ValidateToken(id, validationParams, out st);

                if (principal.Identity.IsAuthenticated)
                {
                    return new TokenValidationResult<IRefreshToken>(new SentinelPrincipal(principal), entity);
                }
            }

            return new TokenValidationResult<IRefreshToken>(SentinelPrincipal.Anonymous, null);
        }
    }
}