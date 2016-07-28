namespace Sentinel.OAuth.Extensions
{
    using System.Linq;
    using System.Security.Claims;

    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Models.Identity;

    public static class ClaimsPrincipalExtensions
    {
        /// <summary>Gets the identity with the specified authentication type.</summary>
        /// <param name="principal">The principal to act on.</param>
        /// <param name="authenticationType">The authentication type.</param>
        /// <returns>The identity.</returns>
        public static ISentinelIdentity GetIdentity(this ClaimsPrincipal principal, string authenticationType)
        {
            var i = principal.Identities.FirstOrDefault(x => x.AuthenticationType == authenticationType);

            if (i == null)
            {
                return SentinelIdentity.Anonymous;
            }

            return new SentinelIdentity(i);
        }
    }
}