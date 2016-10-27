namespace Sentinel.OAuth.Core.Managers
{
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using System.Threading.Tasks;

    using Common.Logging;

    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Models;

    /// <summary>A base user manager.</summary>
    public abstract class BaseUserManager : IUserManager
    {
        /// <summary>Initializes a new instance of the BaseUserManager class.</summary>
        /// <param name="logger">The logger.</param>
        /// <param name="passwordCryptoProvider">The crypto provider.</param>
        /// <param name="asymmetricCryptoProvider">The asymmetric crypto provider.</param>
        /// <param name="userRepository">The user repository.</param>
        /// <param name="userApiKeyRepository">The user API key repository.</param>
        /// <param name="clientRepository">The client repository.</param>
        protected BaseUserManager(ILog logger, IPasswordCryptoProvider passwordCryptoProvider, IAsymmetricCryptoProvider asymmetricCryptoProvider, IUserRepository userRepository, IUserApiKeyRepository userApiKeyRepository, IClientRepository clientRepository)
        {
            this.Logger = logger;
            this.PasswordCryptoProvider = passwordCryptoProvider;
            this.AsymmetricCryptoProvider = asymmetricCryptoProvider;
            this.UserRepository = userRepository;
            this.UserApiKeyRepository = userApiKeyRepository;
            this.ClientRepository = clientRepository;
        }

        /// <summary>Gets the logger.</summary>
        /// <value>The logger.</value>
        protected ILog Logger { get; private set; }

        /// <summary>Gets the crypto provider.</summary>
        /// <value>The crypto provider.</value>
        protected IPasswordCryptoProvider PasswordCryptoProvider { get; private set; }

        /// <summary>Gets the asymmetric crypto provider.</summary>
        /// <value>The asymmetric crypto provider.</value>
        protected IAsymmetricCryptoProvider AsymmetricCryptoProvider { get; private set; }

        /// <summary>Gets the user repository.</summary>
        /// <value>The user repository.</value>
        protected IUserRepository UserRepository { get; private set; }

        /// <summary>Gets the user API key repository.</summary>
        /// <value>The user API key repository.</value>
        protected IUserApiKeyRepository UserApiKeyRepository { get; private set; }

        /// <summary>Gets the client repository.</summary>
        /// <value>The client repository.</value>
        protected IClientRepository ClientRepository { get; private set; }

        /// <summary>Creates a user.</summary>
        /// <param name="userId">Identifier for the user.</param>
        /// <param name="firstName">The person's first name.</param>
        /// <param name="lastName">The person's last name.</param>
        /// <returns>The new user.</returns>
        public abstract Task<CreateUserResult> CreateUser(string userId, string firstName, string lastName);

        /// <summary>Creates an API key.</summary>
        /// <param name="userId">Identifier for the user.</param>
        /// <param name="name">The name.</param>
        /// <param name="description">The description.</param>
        /// <returns>The new API key.</returns>
        public abstract Task<CreateUserApiKeyResult> CreateApiKey(object userId, string name, string description);

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