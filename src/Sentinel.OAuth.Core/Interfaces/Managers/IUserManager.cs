namespace Sentinel.OAuth.Core.Interfaces.Managers
{
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Interfaces.Identity;

    public interface IUserManager
    {
        /// <summary>
        /// Authenticates the user using username and password.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="password">The password.</param>
        /// <returns>The client principal.</returns>
        Task<ISentinelPrincipal> AuthenticateUserWithPasswordAsync(string username, string password);
    }
}