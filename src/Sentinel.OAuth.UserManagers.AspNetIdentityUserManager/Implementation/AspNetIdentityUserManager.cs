namespace Sentinel.OAuth.UserManagers.AspNetIdentityUserManager.Implementation
{
    using System;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Microsoft.AspNet.Identity;

    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Implementation;
    using Sentinel.OAuth.Implementation.Providers;
    using Sentinel.OAuth.Models.Identity;
    using Sentinel.OAuth.UserManagers.AspNetIdentityUserManager.Models;

    public class AspNetIdentityUserManager : UserManager<User>, IUserManager
    {
        /// <summary>
        /// Initializes a new instance of the AspNetIdentityUserManager
        /// class.
        /// </summary>
        /// <param name="store">The store.</param>
        public AspNetIdentityUserManager(IUserStore<User> store)
            : base(store)
        {
            this.ClaimsIdentityFactory = new AspNetIdentityClaimsIdentityFactory();
            this.PasswordHasher = new AspNetIdentityPasswordHasher(new PBKDF2CryptoProvider());
        }

        /// <summary>Authenticates the user using username and password.</summary>
        /// <param name="username">The username.</param>
        /// <param name="password">The password.</param>
        /// <returns>The user principal.</returns>
        public async Task<ISentinelPrincipal> AuthenticateUserWithPasswordAsync(string username, string password)
        {
            var user = await this.FindByNameAsync(username);

            if (user != null)
            {
                var valid = this.PasswordHasher.VerifyHashedPassword(password, user.PasswordHash);

                if (valid == PasswordVerificationResult.Success)
                {
                    var identity = await this.CreateIdentityAsync(user, AuthenticationType.OAuth);
                    return new SentinelPrincipal(identity);
                }
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
            var user = await this.FindByNameAsync(username);

            if (user != null)
            {
                var identity = await this.CreateIdentityAsync(user, AuthenticationType.OAuth);
                return new SentinelPrincipal(identity);
            }

            return SentinelPrincipal.Anonymous;
        }

        /// <summary>Authenticate the user using an API key.</summary>
        /// <param name="digest">The digest.</param>
        /// <returns>The user principal.</returns>
        public async Task<ISentinelPrincipal> AuthenticateUserWithApiKeyAsync(ApiKeyAuthenticationDigest digest)
        {
            throw new NotImplementedException();
        }
    }
}