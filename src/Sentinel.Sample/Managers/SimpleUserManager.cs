namespace Sentinel.Sample.Managers
{
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Core.Models.OAuth;
    using Sentinel.OAuth.Models.Identity;

    public class SimpleUserManager : IUserManager
    {
        private readonly IAsymmetricCryptoProvider asymmetricCryptoProvider;

        private readonly IPasswordCryptoProvider passwordCryptoProvider;

        public SimpleUserManager(IPasswordCryptoProvider passwordCryptoProvider, IAsymmetricCryptoProvider asymmetricCryptoProvider)
        {
            this.passwordCryptoProvider = passwordCryptoProvider;
            this.asymmetricCryptoProvider = asymmetricCryptoProvider;
        }

        public async Task<CreateUserResult> CreateUser(string userId, string firstName, string lastName)
        {
            var user = new User() { UserId = userId, FirstName = firstName, LastName = lastName, Enabled = true };

            string password;
            user.Password = this.passwordCryptoProvider.CreateHash(out password, 8);

            return new CreateUserResult()
                       {
                           User = user,
                           Password = password
                       };
        }

        public async Task<CreateUserApiKeyResult> CreateApiKey(object userId, string name, string description)
        {
            var apiKey = new UserApiKey() { UserId = userId.ToString(), Name = name, Description = description };

            string privateKey;
            apiKey.ApiKey = this.asymmetricCryptoProvider.GenerateKeys(out privateKey);

            return new CreateUserApiKeyResult()
            {
                ApiKey = apiKey,
                PrivateKey = privateKey
            };
        }

        /// <summary>Authenticates the user using username and password.</summary>
        /// <param name="username">The username.</param>
        /// <param name="password">The password.</param>
        /// <returns>The client principal.</returns>
        public async Task<ISentinelPrincipal> AuthenticateUserWithPasswordAsync(string username, string password)
        {
            // Just return an authenticated principal with the username as name if the username matches the password
            if (username == password)
            {
                // Name is required to authenticate a user
                // NameIdentifier and IdentityProvider is required for MVC's AntiForgeryToken. Can be overridden by setting AntiForgeryConfig.UniqueClaimTypeIdentifier.
                return
                    new SentinelPrincipal(
                        new SentinelIdentity(
                            AuthenticationType.OAuth,
                            new SentinelClaim(JwtClaimType.Name, username),
                            new SentinelClaim(JwtClaimType.Subject, username),
                            new SentinelClaim(ClaimType.IdentityProvider, "Sentinel")));
            }

            return SentinelPrincipal.Anonymous;
        }

        /// <summary>
        /// Authenticates the user using username only. This method is used to get new user claims after
        /// a refresh token has been used. You can therefore assume that the user is already logged in.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <returns>The user principal.</returns>
        public async Task<ISentinelPrincipal> AuthenticateUserAsync(string username)
        {
            return new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(JwtClaimType.Name, username)));
        }

        public async Task<ISentinelPrincipal> AuthenticateUserWithSignatureAsync(SignatureAuthenticationDigest digest)
        {
            return new SentinelPrincipal(new SentinelIdentity(AuthenticationType.Signature, new SentinelClaim(JwtClaimType.Name, digest.UserId)));
        }

        public async Task<ISentinelPrincipal> AuthenticateUserWithApiKeyAsync(BasicAuthenticationDigest digest)
        {
            return new SentinelPrincipal(new SentinelIdentity(AuthenticationType.Signature, new SentinelClaim(JwtClaimType.Name, digest.UserId)));
        }
    }
}