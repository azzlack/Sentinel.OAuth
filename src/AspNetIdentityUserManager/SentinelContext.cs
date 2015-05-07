namespace Sentinel.OAuth.UserManagers.AspNetIdentityUserManager
{
    using Microsoft.AspNet.Identity.EntityFramework;

    using Sentinel.OAuth.UserManagers.AspNetIdentityUserManager.Models;

    public class SentinelContext : IdentityDbContext<User>
    {
        public SentinelContext(string connectionString)
            : base(connectionString, false)
        {
            this.Configuration.ProxyCreationEnabled = false;
            this.Configuration.LazyLoadingEnabled = false;
        }
    }
}