namespace Sentinel.OAuth.Extensions
{
    using System.Security.Claims;

    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Models.Identity;

    public static class ClaimsIdentityExtensions
    {
        /// <summary>
        ///     A ClaimsIdentity extension method that converts a principal to a sentinel principal.
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
    }
}