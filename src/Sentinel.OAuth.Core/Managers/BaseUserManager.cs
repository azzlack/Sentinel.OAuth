namespace Sentinel.OAuth.Core.Managers
{
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Core.Interfaces.Providers;

    /// <summary>A base user manager.</summary>
    public abstract class BaseUserManager : IUserManager
    {
        /// <summary>
        /// Initializes a new instance of the BaseUserManager class.
        /// </summary>
        /// <param name="cryptoProvider">The crypto provider.</param>
        protected BaseUserManager(ICryptoProvider cryptoProvider)
        {
            this.CryptoProvider = cryptoProvider;
        }

        /// <summary>Gets the crypto provider.</summary>
        /// <value>The crypto provider.</value>
        protected ICryptoProvider CryptoProvider { get; private set; }

        /// <summary>Authenticates the user using username and password.</summary>
        /// <param name="username">The username.</param>
        /// <param name="password">The password.</param>
        /// <returns>The user principal.</returns>
        public abstract Task<ISentinelPrincipal> AuthenticateUserWithPasswordAsync(string username, string password);

        /// <summary>
        /// Authenticates the user using username only. This method is used to get new user claims after
        /// a refresh token has been used. You can therefore assume that the user is already logged in.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <returns>The user principal.</returns>
        public abstract Task<ISentinelPrincipal> AuthenticateUserAsync(string username);
    }
}