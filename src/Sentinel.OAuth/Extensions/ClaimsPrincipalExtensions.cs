namespace Sentinel.OAuth.Extensions
{
    using System.Security.Claims;

    using Newtonsoft.Json;

    using Sentinel.OAuth.Core.Models.Identity;

    public static class ClaimsPrincipalExtensions
    {
        /// <summary>
        /// Converts the claim principal to a json string
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <returns>A json string representing the claims principal.</returns>
        public static string AsJson(this ClaimsPrincipal principal)
        {
            var p = new JsonPrincipal(principal);

            return JsonConvert.SerializeObject(p);
        }
    }
}