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
        /// Initializes a new instance of the Sentinel.OAuth.Core.Models.Managers.BaseUserManager
        /// class.
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
        /// <returns>The client principal.</returns>
        public abstract Task<ISentinelPrincipal> AuthenticateUserWithPasswordAsync(string username, string password);
    }
}