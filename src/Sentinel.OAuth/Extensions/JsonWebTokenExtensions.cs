namespace Sentinel.OAuth.Extensions
{
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Models.Tokens;
    using Sentinel.OAuth.Models.Identity;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;

    public static class JsonWebTokenExtensions
    {
        /// <summary>Converts the Json Web Token to a list of <see cref="ISentinelClaim"/>.</summary>
        /// <param name="jwt">The token to act on.</param>
        /// <returns>The claims.</returns>
        public static IEnumerable<ISentinelClaim> ToSentinelClaims(this JsonWebToken jwt)
        {
            return jwt.Payload.Select(x => new SentinelClaim(x.Key, x.Value.ToString()));
        }

        /// <summary>Converts the Json Web Token to a list of <see cref="Claim"/>.</summary>
        /// <param name="jwt">The token to act on.</param>
        /// <returns>The claims.</returns>
        public static IEnumerable<Claim> ToClaims(this JsonWebToken jwt)
        {
            return jwt.Payload.Select(x => new Claim(x.Key, x.Value.ToString()));
        }
    }
}