namespace Sentinel.OAuth.Core.Interfaces.Managers
{
    using System.Security.Claims;
    using System.Threading.Tasks;

    public interface IUserManager
    {
        /// <summary>
        /// Authenticates the user using username and password.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="password">The password.</param>
        /// <returns>The client principal.</returns>
        Task<ClaimsPrincipal> AuthenticateUserWithPasswordAsync(string username, string password);
    }
}