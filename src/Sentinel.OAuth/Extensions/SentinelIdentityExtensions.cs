namespace Sentinel.OAuth.Extensions
{
    using System.Collections.Generic;
    using System.Security.Claims;

    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Models.OAuth.Http;

    public static class SentinelIdentityExtensions
    {
        /// <summary>
        ///     An ISentinelIdentity extension method that converts an identity to the claims
        ///     identity.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <returns>A ClaimsIdentity.</returns>
        public static ClaimsIdentity ToClaimsIdentity(this ISentinelIdentity identity)
        {
            var i = new ClaimsIdentity(identity.Claims.ToClaims(), identity.AuthenticationType);

            // Add name identifier claim if it doesnt exist
            if (!i.HasClaim(x => x.Type == ClaimTypes.NameIdentifier))
            {
                i.AddClaim(new Claim(ClaimTypes.NameIdentifier, i.Name));
            }

            return i;
        }

        /// <summary>
        /// An ISentinelIdentity extension method that converts an identity to an identity response.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <returns>An IdentityResponse.</returns>
        public static IdentityResponse ToIdentityResponse(this ISentinelIdentity identity)
        {
            var claims = new List<KeyValuePair<string, string>>();

            foreach (var claim in identity.Claims)
            {
                claims.Add(new KeyValuePair<string, string>(claim.Type, claim.Value));
            }

            return new IdentityResponse(claims);
        }
    }
}