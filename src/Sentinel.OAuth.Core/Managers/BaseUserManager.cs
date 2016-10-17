namespace Sentinel.OAuth.Core.Managers
{
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Models;

    /// <summary>A base user manager.</summary>
    public abstract class BaseUserManager : IUserManager
    {
        /// <summary>Initializes a new instance of the BaseUserManager class.</summary>
        /// <param name="cryptoProvider">The crypto provider.</param>
        /// <param name="asymmetricCryptoProvider">The asymmetric crypto provider.</param>
        /// <param name="userRepository">The user repository.</param>
        /// <param name="userApiKeyRepository">The user API key repository.</param>
        protected BaseUserManager(ICryptoProvider cryptoProvider, IAsymmetricCryptoProvider asymmetricCryptoProvider, IUserRepository userRepository, IUserApiKeyRepository userApiKeyRepository)
        {
            this.CryptoProvider = cryptoProvider;
            this.AsymmetricCryptoProvider = asymmetricCryptoProvider;
            this.UserRepository = userRepository;
            this.UserApiKeyRepository = userApiKeyRepository;
        }

        /// <summary>Gets the crypto provider.</summary>
        /// <value>The crypto provider.</value>
        protected ICryptoProvider CryptoProvider { get; private set; }

        /// <summary>Gets the asymmetric crypto provider.</summary>
        /// <value>The asymmetric crypto provider.</value>
        protected IAsymmetricCryptoProvider AsymmetricCryptoProvider { get; private set; }

        /// <summary>Gets the user repository.</summary>
        /// <value>The user repository.</value>
        protected IUserRepository UserRepository { get; private set; }

        /// <summary>Gets the user API key repository.</summary>
        /// <value>The user API key repository.</value>
        protected IUserApiKeyRepository UserApiKeyRepository { get; private set; }

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

        /// <summary>Authenticate the user using an API key.</summary>
        /// <param name="digest">The digest.</param>
        /// <returns>The user principal.</returns>
        public abstract Task<ISentinelPrincipal> AuthenticateUserWithSignatureAsync(SignatureAuthenticationDigest digest);

        /// <summary>Authenticate the user using an API key.</summary>
        /// <param name="digest">The digest.</param>
        /// <returns>The user principal.</returns>
        public abstract Task<ISentinelPrincipal> AuthenticateUserWithApiKeyAsync(BasicAuthenticationDigest digest);
    }
}