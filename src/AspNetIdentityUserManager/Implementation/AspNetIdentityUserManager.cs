namespace Sentinel.OAuth.UserManagers.AspNetIdentityUserManager.Implementation
{
    using System.Threading.Tasks;

    using Microsoft.AspNet.Identity;

    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
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
        }

        public Task<ISentinelPrincipal> AuthenticateUserWithPasswordAsync(string username, string password)
        {
            throw new System.NotImplementedException();
        }

        public Task<ISentinelPrincipal> AuthenticateUserAsync(string username)
        {
            throw new System.NotImplementedException();
        }
    }
}