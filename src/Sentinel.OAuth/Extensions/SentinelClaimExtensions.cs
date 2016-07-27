namespace Sentinel.OAuth.Extensions
{
    using System.Collections.Generic;
    using System.Security.Claims;

    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Models.Identity;

    public static class SentinelClaimExtensions
    {
        /// <summary>Converts the sentinel claims to identity model claims.</summary>
        /// <param name="claims">The claims to act on.</param>
        /// <returns>The claim.</returns>
        public static IEnumerable<Claim> ToClaims(this IEnumerable<ISentinelClaim> claims)
        {
            foreach (var claim in claims)
            {
                if (claim is SentinelClaim)
                {
                    yield return (SentinelClaim)claim;
                }
                else
                {
                    yield return new Claim(claim.Type, claim.Value);
                }
            }
        } 
    }
}