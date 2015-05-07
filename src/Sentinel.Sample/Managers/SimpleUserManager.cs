namespace Sentinel.Sample.Managers
{
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Models.Identity;

    public class SimpleUserManager : IUserManager
    {
        /// <summary>Authenticates the user using username and password.</summary>
        /// <param name="username">The username.</param>
        /// <param name="password">The password.</param>
        /// <returns>The client principal.</returns>
        public async Task<ISentinelPrincipal> AuthenticateUserWithPasswordAsync(string username, string password)
        {
            // Just return an authenticated principal with the username as name if the username matches the password
            if (username == password)
            {
                return new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, username)));
            }

            return SentinelPrincipal.Anonymous;
        }

        /// <summary>
        /// Authenticates the user using username only. This method is used to get new user claims after
        /// a refresh token has been used. You can therefore assume that the user is already logged in.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <returns>The user principal.</returns>
        public async Task<ISentinelPrincipal> AuthenticateUserAsync(string username)
        {
            return new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, username)));
        }
    }
}