namespace Sentinel.OAuth.Extensions
{
    using System;

    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Models.Tokens;
    using Sentinel.OAuth.Models.Identity;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;

    using Sentinel.OAuth.Implementation.Validators;

    public static class JsonWebTokenExtensions
    {
        /// <summary>A JsonWebToken extension method that converts a jwt to an identity.</summary>
        /// <param name="jwt">The token to act on.</param>
        /// <returns>jwt as an ISentinelIdentity.</returns>
        public static ISentinelIdentity ToIdentity(this JsonWebToken jwt)
        {
            return new SentinelIdentity("", jwt);
        }

        /// <summary>Converts the Json Web Token to a list of <see cref="Claim"/>.</summary>
        /// <param name="jwt">The token to act on.</param>
        /// <returns>The claims.</returns>
        public static IEnumerable<Claim> ToClaims(this JsonWebToken jwt)
        {
            return jwt.Payload.Select(x => new Claim(x.Key, x.Value.ToString()));
        }

        /// <summary>Validates the authorization code.</summary>
        /// <exception cref="ArgumentNullException">Thrown when code is null.</exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown when the JWT does not contain a c_hash claim.
        /// </exception>
        /// <param name="jwt">The token to act on.</param>
        /// <param name="code">The code.</param>
        /// <returns>true if it succeeds, false if it fails.</returns>
        public static bool ValidateAuthorizationCode(this JsonWebToken jwt, string code)
        {
            if (string.IsNullOrEmpty(code))
            {
                throw new ArgumentNullException(nameof(code));
            }

            var hash = jwt.Payload.FirstOrDefault(x => x.Key == "c_hash");
            if (hash.Value == null)
            {
                throw new InvalidOperationException("The JWT does not contain a c_hash claim. It is required to validate authentication codes.");
            }

            var validator = new TokenValidator();

            return validator.ValidateAuthorizationCodeHash(code, hash.Value.ToString(), jwt.Header.Algorithm);
        }

        /// <summary>Validates the access token.</summary>
        /// <exception cref="ArgumentNullException">Thrown when access token is null.</exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown when the JWT does not contain a at_hash claim.
        /// </exception>
        /// <param name="jwt">The token to act on.</param>
        /// <param name="accessToken">The access token.</param>
        /// <returns>true if it succeeds, false if it fails.</returns>
        public static bool ValidateAccessToken(this JsonWebToken jwt, string accessToken)
        {
            if (string.IsNullOrEmpty(accessToken))
            {
                throw new ArgumentNullException(nameof(accessToken));
            }

            var hash = jwt.Payload.FirstOrDefault(x => x.Key == "at_hash");
            if (hash.Value == null)
            {
                throw new InvalidOperationException("The JWT does not contain a at_hash claim. It is required to validate authentication codes.");
            }

            var validator = new TokenValidator();

            return validator.ValidateAccessTokenHash(accessToken, hash.Value.ToString(), jwt.Header.Algorithm);
        }

        /// <summary>Validates the token signature.</summary>
        /// <exception cref="ArgumentNullException">Thrown when private key is null.</exception>
        /// <param name="jwt">The token to act on.</param>
        /// <param name="privateKey">The signing private key.</param>
        /// <returns>true if it succeeds, false if it fails.</returns>
        public static bool ValidateSignature(this JsonWebToken jwt, string privateKey)
        {
            if (string.IsNullOrEmpty(privateKey))
            {
                throw new ArgumentNullException(nameof(privateKey));
            }

            var validator = new TokenValidator();

            return validator.ValidateSignature(jwt, privateKey);
        }
    }
}