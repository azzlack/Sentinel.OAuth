namespace Sentinel.OAuth.UserManagers.AspNetIdentityUserManager
{
    using Microsoft.AspNet.Identity.EntityFramework;

    using Sentinel.OAuth.UserManagers.AspNetIdentityUserManager.Models;

    public class SentinelContext : IdentityDbContext<User>
    {
        public SentinelContext()
            : base("DefaultConnection", false)
        {
            this.Configuration.ProxyCreationEnabled = false;
            this.Configuration.LazyLoadingEnabled = false;
        }

        public static SentinelContext Create()
        {
            return new SentinelContext();
        }
    }
}