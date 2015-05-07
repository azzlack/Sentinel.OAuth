namespace Sentinel.OAuth.UserManagers.AspNetIdentityUserManager.Implementation
{
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Microsoft.AspNet.Identity;

    using Sentinel.OAuth.UserManagers.AspNetIdentityUserManager.Models;

    public class AspNetIdentityClaimsIdentityFactory : ClaimsIdentityFactory<User>
    {
        public override async Task<ClaimsIdentity> CreateAsync(UserManager<User, string> manager, User user, string authenticationType)
        {
            var identity = await base.CreateAsync(manager, user, authenticationType);

            identity.AddClaim(new Claim(ClaimTypes.GivenName, user.FirstName));
            identity.AddClaim(new Claim(ClaimTypes.Surname, user.LastName));

            return identity;
        }
    }
}