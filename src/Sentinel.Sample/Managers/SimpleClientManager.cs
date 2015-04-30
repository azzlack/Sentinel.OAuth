namespace Sentinel.Sample.Managers
{
    using System.Collections.Generic;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;

    public class SimpleClientManager : IClientManager
    {
        public async Task<ClaimsPrincipal> AuthenticateClientAsync(string clientId, string redirectUri)
        {
            // Just return an authenticated principal with the client id as name (allows all clients)
            return new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>() { new Claim(ClaimTypes.Name, clientId) }, AuthenticationType.OAuth));
        }

        public async Task<ClaimsPrincipal> AuthenticateClientAsync(string clientId, IEnumerable<string> scope)
        {
            // Just return an authenticated principal with the client id as name (allows all clients)
            return new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>() { new Claim(ClaimTypes.Name, clientId) }, AuthenticationType.OAuth));
        }

        public async Task<ClaimsPrincipal> AuthenticateClientCredentialsAsync(string clientId, string clientSecret)
        {
            // Return an authenticated principal if the client secret matches the client id
            if (clientId == clientSecret)
            {
                return new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>() { new Claim(ClaimTypes.Name, clientId) }, AuthenticationType.OAuth));
            }

            return new ClaimsPrincipal(new ClaimsIdentity());
        }
    }
}