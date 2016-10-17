namespace Sentinel.OAuth.Implementation.Managers
{
    using System;
    using System.Collections.Generic;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Core.Managers;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Core.Models.OAuth;
    using Sentinel.OAuth.Models.Identity;

    public class UserManager : BaseUserManager
    {
        /// <summary>Initializes a new instance of the <see cref="UserManager" /> class.</summary>
        /// <param name="passwordCryptoProvider">The crypto provider.</param>
        /// <param name="asymmetricCryptoProvider">The asymmetric crypto provider.</param>
        /// <param name="userRepository">The user repository.</param>
        /// <param name="userApiKeyRepository">The user API key repository.</param>
        public UserManager(IPasswordCryptoProvider passwordCryptoProvider, IAsymmetricCryptoProvider asymmetricCryptoProvider, IUserRepository userRepository, IUserApiKeyRepository userApiKeyRepository)
            : base(passwordCryptoProvider, asymmetricCryptoProvider, userRepository, userApiKeyRepository)
        {
        }

        /// <summary>Creates a user.</summary>
        /// <param name="userId">Identifier for the user.</param>
        /// <param name="firstName">The person's first name.</param>
        /// <param name="lastName">The person's last name.</param>
        /// <returns>The new user.</returns>
        public override async Task<CreateUserResult> CreateUser(string userId, string firstName, string lastName)
        {
            var user = new User() { UserId = userId, FirstName = firstName, LastName = lastName, Enabled = true };

            string password;
            user.Password = this.PasswordCryptoProvider.CreateHash(out password, 8);

            var result = await this.UserRepository.Create(user);

            if (result != null)
            {
                return new CreateUserResult()
                {
                    User = result,
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
        public override async Task<CreateUserApiKeyResult> CreateApiKey(object userId, string name, string description)
        {
            var apiKey = new UserApiKey() { UserId = userId.ToString(), Name = name, Description = description };

            string privateKey;
            apiKey.ApiKey = this.AsymmetricCryptoProvider.GenerateKeys(out privateKey);

            var result = await this.UserApiKeyRepository.Create(apiKey);

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
        /// <returns>The client principal.</returns>
        public override async Task<ISentinelPrincipal> AuthenticateUserWithPasswordAsync(string username, string password)
        {
            var user = await this.UserRepository.GetUser(username);

            if (user != null && this.PasswordCryptoProvider.ValidateHash(password, user.Password))
            {
                var principal =
                    new SentinelPrincipal(
                        new SentinelIdentity(
                            AuthenticationType.OAuth,
                            new SentinelClaim(JwtClaimType.Name, user.UserId),
                            new SentinelClaim(ClaimTypes.AuthenticationMethod, AuthenticationMethod.UserCredentials),
                            new SentinelClaim(JwtClaimType.GivenName, user.FirstName),
                            new SentinelClaim(JwtClaimType.FamilyName, user.LastName)));

                if (principal.Identity.IsAuthenticated)
                {
                    user.LastLogin = DateTimeOffset.UtcNow;
                    await this.UserRepository.Update(user.GetIdentifier(), user);

                    return principal;
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
        public override async Task<ISentinelPrincipal> AuthenticateUserAsync(string username)
        {
            var user = await this.UserRepository.GetUser(username);

            if (user != null)
            {
                var principal =
                    new SentinelPrincipal(
                        new SentinelIdentity(
                            AuthenticationType.OAuth,
                            new SentinelClaim(JwtClaimType.Name, user.UserId),
                            new SentinelClaim(ClaimTypes.AuthenticationMethod, AuthenticationMethod.UserId),
                            new SentinelClaim(JwtClaimType.GivenName, user.FirstName),
                            new SentinelClaim(JwtClaimType.FamilyName, user.LastName)));

                if (principal.Identity.IsAuthenticated)
                {
                    user.LastLogin = DateTimeOffset.UtcNow;
                    await this.UserRepository.Update(user.GetIdentifier(), user);

                    return principal;
                }
            }

            return SentinelPrincipal.Anonymous;
        }

        /// <summary>Authenticate the user using an API key.</summary>
        /// <param name="digest">The digest.</param>
        /// <returns>The user principal.</returns>
        public override async Task<ISentinelPrincipal> AuthenticateUserWithSignatureAsync(SignatureAuthenticationDigest digest)
        {
            var userKeys = await this.UserApiKeyRepository.GetForUser(digest.UserId);

            var matchingKey = this.ValidateApiKey(userKeys, digest.GetData(), digest.Signature);
            if (matchingKey != null)
            {
                var user = await this.UserRepository.GetUser(matchingKey.UserId);

                if (user != null)
                {
                    var principal =
                        new SentinelPrincipal(
                            new SentinelIdentity(
                                AuthenticationType.Signature,
                                new SentinelClaim(JwtClaimType.Name, user.UserId),
                                new SentinelClaim(ClaimTypes.AuthenticationMethod, AuthenticationMethod.ApiKey),
                                new SentinelClaim(ClaimType.AuthenticationSource, "local"),
                                new SentinelClaim(JwtClaimType.GivenName, user.FirstName),
                                new SentinelClaim(JwtClaimType.FamilyName, user.LastName)));

                    user.LastLogin = DateTimeOffset.UtcNow;
                    await this.UserRepository.Update(user.GetIdentifier(), user);

                    matchingKey.LastUsed = DateTimeOffset.UtcNow;
                    await this.UserApiKeyRepository.Update(matchingKey.GetIdentifier(), matchingKey);

                    return principal;
                }
            }

            return SentinelPrincipal.Anonymous;
        }

        /// <summary>Authenticate the user using an API key.</summary>
        /// <param name="digest">The digest.</param>
        /// <returns>The user principal.</returns>
        public override async Task<ISentinelPrincipal> AuthenticateUserWithApiKeyAsync(BasicAuthenticationDigest digest)
        {
            string data;
            string signature;

            try
            {
                data = this.PasswordCryptoProvider.CreateHash(256);
                signature = this.AsymmetricCryptoProvider.Sign(data, digest.Password);
            }
            catch (ArgumentException)
            {
                return SentinelPrincipal.Anonymous;
            }
            catch (FormatException)
            {
                return SentinelPrincipal.Anonymous;
            }

            var userKeys = await this.UserApiKeyRepository.GetForUser(digest.UserId);

            var matchingKey = this.ValidateApiKey(userKeys, data, signature);
            if (matchingKey != null)
            {
                var user = await this.UserRepository.GetUser(matchingKey.UserId);

                if (user != null)
                {
                    var principal =
                        new SentinelPrincipal(
                            new SentinelIdentity(
                                AuthenticationType.Signature,
                                new SentinelClaim(JwtClaimType.Name, user.UserId),
                                new SentinelClaim(ClaimTypes.AuthenticationMethod, AuthenticationMethod.ApiKey),
                                new SentinelClaim(ClaimType.AuthenticationSource, "local"),
                                new SentinelClaim(JwtClaimType.GivenName, user.FirstName),
                                new SentinelClaim(JwtClaimType.FamilyName, user.LastName)));

                    user.LastLogin = DateTimeOffset.UtcNow;
                    await this.UserRepository.Update(user.GetIdentifier(), user);

                    matchingKey.LastUsed = DateTimeOffset.UtcNow;
                    await this.UserApiKeyRepository.Update(matchingKey.GetIdentifier(), matchingKey);

                    return principal;
                }
            }

            return SentinelPrincipal.Anonymous;
        }

        private IUserApiKey ValidateApiKey(IEnumerable<IUserApiKey> userKeys, string data, string signature)
        {
            foreach (var key in userKeys)
            {
                try
                {
                    // Validate signature using RSA and api key
                    var valid = this.AsymmetricCryptoProvider.ValidateSignature(data, signature, key.ApiKey);

                    if (valid)
                    {
                        return key;
                    }
                }
                catch (ArgumentException)
                {
                    // Signature was invalid, proceed to next
                    continue;
                }
            }

            return null;
        }
    }
}