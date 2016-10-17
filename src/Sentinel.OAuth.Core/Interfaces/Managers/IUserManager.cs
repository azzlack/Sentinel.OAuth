namespace Sentinel.OAuth.Core.Interfaces.Managers
{
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models;

    public interface IUserManager
    {
        /// <summary>Creates a user.</summary>
        /// <param name="userId">Identifier for the user.</param>
        /// <param name="firstName">The person's first name.</param>
        /// <param name="lastName">The person's last name.</param>
        /// <returns>The new user.</returns>
        Task<CreateUserResult> CreateUser(string userId, string firstName, string lastName);

        /// <summary>Creates an API key.</summary>
        /// <param name="userId">Identifier for the user.</param>
        /// <param name="name">The name.</param>
        /// <param name="description">The description.</param>
        /// <returns>The new API key.</returns>
        Task<CreateUserApiKeyResult> CreateApiKey(object userId, string name, string description);

        /// <summary>Authenticates the user using username and password.</summary>
        /// <param name="username">The username.</param>
        /// <param name="password">The password.</param>
        /// <returns>The user principal.</returns>
        Task<ISentinelPrincipal> AuthenticateUserWithPasswordAsync(string username, string password);

        /// <summary>
        /// Authenticates the user using username only.
        /// This method is used to get new user claims after a refresh token has been used. You can therefore assume that the user is already logged in.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <returns>The user principal.</returns>
        Task<ISentinelPrincipal> AuthenticateUserAsync(string username);

        /// <summary>Authenticate the user using an API key.</summary>
        /// <param name="digest">The digest.</param>
        /// <returns>The user principal.</returns>
        Task<ISentinelPrincipal> AuthenticateUserWithSignatureAsync(SignatureAuthenticationDigest digest);

        /// <summary>Authenticate the user using an API key.</summary>
        /// <param name="digest">The digest.</param>
        /// <returns>The user principal.</returns>
        Task<ISentinelPrincipal> AuthenticateUserWithApiKeyAsync(BasicAuthenticationDigest digest);
    }
}