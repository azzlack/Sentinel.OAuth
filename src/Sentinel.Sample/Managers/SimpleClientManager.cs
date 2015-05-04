namespace Sentinel.Sample.Managers
{
    using System.Collections.Generic;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Models.Identity;

    public class SimpleClientManager : IClientManager
    {
        public async Task<ISentinelPrincipal> AuthenticateClientAsync(string clientId, string redirectUri)
        {
            // Just return an authenticated principal with the client id as name (allows all clients)
            return new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, clientId)));
        }

        public async Task<ISentinelPrincipal> AuthenticateClientAsync(string clientId, IEnumerable<string> scope)
        {
            // Just return an authenticated principal with the client id as name (allows all clients)
            return new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, clientId)));
        }

        public async Task<ISentinelPrincipal> AuthenticateClientCredentialsAsync(string clientId, string clientSecret)
        {
            // Return an authenticated principal if the client secret matches the client id
            if (clientId == clientSecret)
            {
                return new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, clientId)));
            }

            return SentinelPrincipal.Anonymous;
        }
    }
}