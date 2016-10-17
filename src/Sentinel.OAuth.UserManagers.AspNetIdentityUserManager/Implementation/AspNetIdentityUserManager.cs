namespace Sentinel.OAuth.UserManagers.AspNetIdentityUserManager.Implementation
{
    using System;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Microsoft.AspNet.Identity;

    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Core.Models.OAuth;
    using Sentinel.OAuth.Implementation;
    using Sentinel.OAuth.Implementation.Providers;
    using Sentinel.OAuth.Models.Identity;

    using IUser = Sentinel.OAuth.Core.Interfaces.Models.IUser;
    using User = Sentinel.OAuth.UserManagers.AspNetIdentityUserManager.Models.User;

    public class AspNetIdentityUserManager : UserManager<User>, IUserManager
    {
        private readonly IUserApiKeyRepository userApiKeyRepository;

        private readonly IPasswordCryptoProvider passwordCryptoProvider;

        private readonly IAsymmetricCryptoProvider asymmetricCryptoProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="AspNetIdentityUserManager" /> class.
        /// </summary>
        /// <param name="store">The store.</param>
        /// <param name="userApiKeyRepository">The user API key repository.</param>
        /// <param name="passwordCryptoProvider">The password crypto provider.</param>
        /// <param name="asymmetricCryptoProvider">The asymmetric crypto provider.</param>
        public AspNetIdentityUserManager(IUserStore<User> store, IUserApiKeyRepository userApiKeyRepository, IPasswordCryptoProvider passwordCryptoProvider, IAsymmetricCryptoProvider asymmetricCryptoProvider)
            : base(store)
        {
            this.userApiKeyRepository = userApiKeyRepository;
            this.passwordCryptoProvider = passwordCryptoProvider;
            this.asymmetricCryptoProvider = asymmetricCryptoProvider;

            this.ClaimsIdentityFactory = new AspNetIdentityClaimsIdentityFactory();
            this.PasswordHasher = new AspNetIdentityPasswordHasher(this.passwordCryptoProvider);
        }

        /// <summary>Creates a user.</summary>
        /// <param name="userId">Identifier for the user.</param>
        /// <param name="firstName">The person's first name.</param>
        /// <param name="lastName">The person's last name.</param>
        /// <returns>The new user.</returns>
        public async Task<CreateUserResult> CreateUser(string userId, string firstName, string lastName)
        {
            var user = new User() { UserName = userId, FirstName = firstName, LastName = lastName };

            string password;
            user.PasswordHash = this.passwordCryptoProvider.CreateHash(out password, 8);

            var result = await this.CreateAsync(user);

            if (result.Succeeded)
            {
                return new CreateUserResult
                           {
                               User = user,
                               Password = password
                           };
            }

            return null;
        }

        /// <summary>Creates an API key.</summary>
        /// <param name="userId">Identifier for the user.</param>
        /// <param name="name">The name.</param>
        /// <param name="description">The description.</param>
        /// <returns>The new API key.</returns>
        public async Task<CreateUserApiKeyResult> CreateApiKey(object userId, string name, string description)
        {
            var apiKey = new UserApiKey() { UserId = userId.ToString(), Name = name, Description = description };

            string privateKey;
            apiKey.ApiKey = this.asymmetricCryptoProvider.GenerateKeys(out privateKey);

            var result = await this.userApiKeyRepository.Create(apiKey);

            if (result != null)
            {
                return new CreateUserApiKeyResult()
                {
                    ApiKey = result,
                    PrivateKey = privateKey
                };
            }

            return null;
        }

        /// <summary>Authenticates the user using username and password.</summary>
        /// <param name="username">The username.</param>
        /// <param name="password">The password.</param>
        /// <returns>The user principal.</returns>
        public virtual async Task<ISentinelPrincipal> AuthenticateUserWithPasswordAsync(string username, string password)
        {
            var user = await this.FindByNameAsync(username);

            if (user != null)
            {
                var valid = this.PasswordHasher.VerifyHashedPassword(password, user.PasswordHash);

                if (valid == PasswordVerificationResult.Success)
                {
                    var identity = await this.CreateIdentityAsync(user, AuthenticationType.OAuth);
                    return new SentinelPrincipal(identity);
                }
            }

            return SentinelPrincipal.Anonymous;
        }

        /// <summary>
        /// Authenticates the user using username only. This method is used to get new user claims after
        /// a refresh token has been used. You can therefore assume that the user is already logged in.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <returns>The user principal.</returns>
        public virtual async Task<ISentinelPrincipal> AuthenticateUserAsync(string username)
        {
            var user = await this.FindByNameAsync(username);

            if (user != null)
            {
                var identity = await this.CreateIdentityAsync(user, AuthenticationType.OAuth);
                return new SentinelPrincipal(identity);
            }

            return SentinelPrincipal.Anonymous;
        }

        /// <summary>Authenticate the user using an API key.</summary>
        /// <param name="digest">The digest.</param>
        /// <returns>The user principal.</returns>
        public virtual async Task<ISentinelPrincipal> AuthenticateUserWithSignatureAsync(SignatureAuthenticationDigest digest)
        {
            throw new NotImplementedException();
        }

        public Task<ISentinelPrincipal> AuthenticateUserWithApiKeyAsync(BasicAuthenticationDigest digest)
        {
            throw new NotImplementedException();
        }
    }
}