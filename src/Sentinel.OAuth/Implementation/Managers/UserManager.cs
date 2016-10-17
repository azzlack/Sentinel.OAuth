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
    using Sentinel.OAuth.Models.Identity;

    public class UserManager : BaseUserManager
    {
        /// <summary>Initializes a new instance of the <see cref="UserManager" /> class.</summary>
        /// <param name="cryptoProvider">The crypto provider.</param>
        /// <param name="asymmetricCryptoProvider">The asymmetric crypto provider.</param>
        /// <param name="userRepository">The user repository.</param>
        /// <param name="userApiKeyRepository">The user API key repository.</param>
        public UserManager(ICryptoProvider cryptoProvider, IAsymmetricCryptoProvider asymmetricCryptoProvider, IUserRepository userRepository, IUserApiKeyRepository userApiKeyRepository)
            : base(cryptoProvider, asymmetricCryptoProvider, userRepository, userApiKeyRepository)
        {
        }

        /// <summary>Authenticates the user using username and password.</summary>
        /// <param name="username">The username.</param>
        /// <param name="password">The password.</param>
        /// <returns>The client principal.</returns>
        public override async Task<ISentinelPrincipal> AuthenticateUserWithPasswordAsync(string username, string password)
        {
            var user = await this.UserRepository.GetUser(username);

            if (user != null && this.CryptoProvider.ValidateHash(password, user.Password))
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
                data = this.CryptoProvider.CreateHash(256);
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