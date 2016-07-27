namespace Sentinel.OAuth.Implementation.Validators
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using Sentinel.OAuth.Core.Interfaces.Validators;
    using Sentinel.OAuth.Core.Models.Tokens;

    public class TokenValidator : ITokenValidator
    {
        /// <summary>Validates the authorization code hash.</summary>
        /// <param name="code">The code.</param>
        /// <param name="hash">The hash.</param>
        /// <param name="algorithm">The hashing algorithm.</param>
        /// <returns>true if it succeeds, false if it fails.</returns>
        public bool ValidateAuthorizationCodeHash(string code, string hash, string algorithm)
        {
            using (var alg = this.GetAlgorithm(algorithm))
            {
                // Create hash for code
                var hashedCode = alg.ComputeHash(Encoding.UTF8.GetBytes(code));

                // Compare c_hash with first 16 bytes of hashed code
                if (hash == Convert.ToBase64String(hashedCode.Take(16).ToArray()))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>Validates the access token hash.</summary>
        /// <param name="accessToken">The access token.</param>
        /// <param name="hash">The hash.</param>
        /// <param name="algorithm">The hashing algorithm.</param>
        /// <returns>true if it succeeds, false if it fails.</returns>
        public bool ValidateAccessTokenHash(string accessToken, string hash, string algorithm)
        {
            using (var alg = this.GetAlgorithm(algorithm))
            {
                // Create hash for access token
                var hashedCode = alg.ComputeHash(Encoding.UTF8.GetBytes(accessToken));

                // Compare at_hash with first 16 bytes of hashed access token
                if (hash == Convert.ToBase64String(hashedCode.Take(16).ToArray()))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>Validates the token signature.</summary>
        /// <param name="jwt">The token.</param>
        /// <param name="key">The key.</param>
        /// <returns>true if it succeeds, false if it fails.</returns>
        public bool ValidateSignature(JsonWebToken jwt, string key)
        {
            throw new NotImplementedException();
        }

        /// <summary>Gets an algorithm.</summary>
        /// <exception cref="ArgumentException">
        /// Thrown when one or more arguments have unsupported or illegal values.
        /// </exception>
        /// <param name="algorithm">The hashing algorithm.</param>
        /// <returns>The algorithm.</returns>
        private HashAlgorithm GetAlgorithm(string algorithm)
        {
            if (algorithm == "HS256")
            {
                return new SHA256CryptoServiceProvider();
            }

            if (algorithm == "HS384")
            {
                return new SHA384CryptoServiceProvider();
            }

            if (algorithm == "HS512")
            {
                return new SHA512CryptoServiceProvider();
            }

            throw new ArgumentException($"The algorithm '{algorithm}' is not supported");
        }
    }
}
