namespace Sentinel.OAuth.Extensions
{
    using Newtonsoft.Json;
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Models.Identity;
    using System.Linq;
    using System.Security.Claims;
    using System.Security.Principal;

    public static class PrincipalExtensions
    {
        /// <summary>
        /// Converts the claim principal to a json string
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <returns>A json string representing the claims principal.</returns>
        public static string ToJson(this IPrincipal principal)
        {
            var p = new SentinelPrincipal(principal);

            return JsonConvert.SerializeObject(p);
        }

        /// <summary>
        ///     A ClaimsPrincipal extension method that converts a principal to a sentinel principal.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <returns>A SentinelPrincipal.</returns>
        public static ISentinelPrincipal AsSentinelPrincipal(this ClaimsPrincipal principal)
        {
            return new SentinelPrincipal(principal);
        }

        /// <summary>
        ///     A ClaimsPrincipal extension method that converts a principal to a sentinel principal.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <returns>A SentinelPrincipal.</returns>
        public static ISentinelPrincipal AsSentinelPrincipal(this ClaimsIdentity identity)
        {
            return new SentinelPrincipal(identity.AsSentinelIdentity());
        }

        /// <summary>
        ///     A ClaimsIdentity extension method that converts an identity to a sentinel identity.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <returns>An ISentinelIdentity.</returns>
        public static ISentinelIdentity AsSentinelIdentity(this ClaimsIdentity identity)
        {
            return new SentinelIdentity(identity);
        }

        /// <summary>
        ///     An ISentinelIdentity extension method that converts an identity to the claims
        ///     identity.
        /// </summary>
        /// <param name="identity">The identity.</param>
        /// <returns>A ClaimsIdentity.</returns>
        public static ClaimsIdentity AsClaimsIdentity(this ISentinelIdentity identity)
        {
            return new ClaimsIdentity(identity.Claims.Select(x => new Claim(x.Type, x.Value ?? "")), identity.AuthenticationType);
        }
    }
}