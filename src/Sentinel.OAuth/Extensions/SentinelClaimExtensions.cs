namespace Sentinel.OAuth.Extensions
{
    using System.Collections.Generic;
    using System.IdentityModel.Tokens;
    using System.Security.Claims;

    using Sentinel.OAuth.Core.Interfaces.Identity;

    public static class SentinelClaimExtensions
    {
        /// <summary>Converts the sentinel claims to identity model claims.</summary>
        /// <param name="claims">The claims to act on.</param>
        /// <returns>The claim.</returns>
        public static IEnumerable<Claim> ToClaims(this IEnumerable<ISentinelClaim> claims)
        {
            foreach (var claim in claims)
            {
                var c = new Claim(claim.Type, claim.Value);

                if (!string.IsNullOrEmpty(claim.Alias))
                {
                    c.Properties.Add(JwtSecurityTokenHandler.ShortClaimTypeProperty, claim.Alias);
                }

                yield return c;
            }
        } 
    }
}