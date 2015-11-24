namespace Sentinel.OAuth.Implementation.Providers
{
    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Core.Models.OAuth;
    using Sentinel.OAuth.Extensions;
    using Sentinel.OAuth.Models.Identity;
    using Sentinel.OAuth.Models.Providers;
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens;
    using System.Linq;
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

            string token;
            var hashedToken = this.configuration.CryptoProvider.CreateHash(out token, 256);

            // Create authorization code hash
            var codeHash = this.configuration.CryptoProvider.CreateHash(token, false).ToCharArray();

            // Add extra claims
            userPrincipal.Identity.AddClaim(JwtClaimType.Subject, userPrincipal.Identity.Name);
            userPrincipal.Identity.AddClaim(JwtClaimType.AuthorizationCodeHash, Convert.ToBase64String(Encoding.ASCII.GetBytes(codeHash, 0, codeHash.Length / 2)));

            var jwt = new JwtSecurityToken(
                this.configuration.Issuer.AbsoluteUri,
                clientId,
                userPrincipal.Identity.Claims.ToClaims(),
                DateTime.UtcNow,
                expireTime.UtcDateTime,
                this.configuration.SigningCredentials);

            var ticket = this.tokenHandler.WriteToken(jwt);

            var authorizationCode = new AuthorizationCode()
            {
                ClientId = clientId,
                RedirectUri = redirectUri,
                Subject = userPrincipal.Identity.Name,
                Scope = scope,
                Code = hashedToken,
                Ticket = ticket,
                ValidTo = expireTime
            };

            return new TokenCreationResult<IAuthorizationCode>(token, authorizationCode);
        }

        /// <summary>Validates an authorization code.</summary>
        /// <param name="authorizationCodes">The authorization codes to validate against.</param>
        /// <param name="code">The code.</param>
        /// <returns>The access token if valid, <c>null</c> otherwise.</returns>
        public async Task<TokenValidationResult<IAuthorizationCode>> ValidateAuthorizationCode(IEnumerable<IAuthorizationCode> authorizationCodes, string code)
        {
            var entity = authorizationCodes.FirstOrDefault(x => this.configuration.CryptoProvider.ValidateHash(code, x.Code));

            if (entity != null)
            {
                var validationParams = new TokenValidationParameters()
                {
                    ValidAudience = entity.ClientId,
                    IssuerSigningToken = this.configuration.SigningKey,
                    ValidIssuer = this.configuration.Issuer.AbsoluteUri
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
            // Create token
            string token;
            var hashedToken = this.configuration.CryptoProvider.CreateHash(out token, 512);

            // Create access token hash
            var tokenHash = this.configuration.CryptoProvider.CreateHash(token, false).ToCharArray();

            // Add extra claims
            userPrincipal.Identity.AddClaim(JwtClaimType.Subject, userPrincipal.Identity.Name);
            userPrincipal.Identity.AddClaim(JwtClaimType.AccessTokenHash, Convert.ToBase64String(Encoding.ASCII.GetBytes(tokenHash, 0, tokenHash.Length / 2)));

            var jwt = new JwtSecurityToken(
                this.configuration.Issuer.AbsoluteUri,
                clientId,
                userPrincipal.Identity.Claims.ToClaims(),
                DateTime.UtcNow,
                expireTime.UtcDateTime,
                this.configuration.SigningCredentials);

            var idToken = this.tokenHandler.WriteToken(jwt);

            var accessToken = new AccessToken()
            {
                ClientId = clientId,
                RedirectUri = redirectUri,
                Subject = userPrincipal.Identity.Name,
                Scope = scope,
                Token = hashedToken,
                Ticket = idToken,
                ValidTo = expireTime
            };

            return new TokenCreationResult<IAccessToken>(token, accessToken);
        }

        /// <summary>Validates the access token.</summary>
        /// <param name="accessTokens">The access tokens to validate against.</param>
        /// <param name="token">The token.</param>
        /// <returns>The token principal if valid, <c>null</c> otherwise.</returns>
        public async Task<TokenValidationResult<IAccessToken>> ValidateAccessToken(IEnumerable<IAccessToken> accessTokens, string token)
        {
            var entity = accessTokens.FirstOrDefault(x => this.configuration.CryptoProvider.ValidateHash(token, x.Token));

            if (entity != null)
            {
                var validationParams = new TokenValidationParameters()
                {
                    ValidAudience = entity.ClientId,
                    IssuerSigningToken = this.configuration.SigningKey,
                    ValidIssuer = this.configuration.Issuer.AbsoluteUri
                };

                SecurityToken st;
                var principal = this.tokenHandler.ValidateToken(entity.Ticket, validationParams, out st);

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
            string token;
            var hashedToken = this.configuration.CryptoProvider.CreateHash(out token, 2048);

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

        /// <summary>Validates the refresh token.</summary>
        /// <param name="refreshTokens">The refresh tokens to validate against.</param>
        /// <param name="token">The token.</param>
        /// <returns>The token principal if valid, <c>null</c> otherwise.</returns>
        public async Task<TokenValidationResult<IRefreshToken>> ValidateRefreshToken(IEnumerable<IRefreshToken> refreshTokens, string token)
        {
            var entity = refreshTokens.FirstOrDefault(x => this.configuration.CryptoProvider.ValidateHash(token, x.Token));

            if (entity != null)
            {
                var identity = new SentinelIdentity(
                    AuthenticationType.OAuth,
                    new SentinelClaim(ClaimType.Name, entity.Subject),
                    new SentinelClaim(ClaimType.Client, entity.ClientId),
                    new SentinelClaim(ClaimType.RedirectUri, entity.RedirectUri));

                if (entity.Scope != null)
                {
                    identity.AddClaim(ClaimType.Scope, string.Join(" ", entity.Scope));
                }

                if (identity.IsAuthenticated)
                {
                    return new TokenValidationResult<IRefreshToken>(new SentinelPrincipal(identity), entity);
                }
            }

            return new TokenValidationResult<IRefreshToken>(SentinelPrincipal.Anonymous, null);
        }
    }
}