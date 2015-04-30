namespace Sentinel.Sample.Managers
{
    using System.Collections.Generic;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;

    public class SimpleUserManager : IUserManager
    {
        public async Task<ClaimsPrincipal> AuthenticateUserWithPasswordAsync(string username, string password)
        {
            // Just return an authenticated principal with the username as name if the username matches the password
            if (username == password)
            {
                return new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>() { new Claim(ClaimTypes.Name, username) }, AuthenticationType.OAuth));
            }

            return new ClaimsPrincipal(new ClaimsIdentity());
        }
    }
}