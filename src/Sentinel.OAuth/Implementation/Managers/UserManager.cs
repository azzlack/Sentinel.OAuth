namespace Sentinel.OAuth.Implementation.Managers
{
    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Core.Managers;
    using Sentinel.OAuth.Models.Identity;
    using System.Security.Claims;
    using System.Threading.Tasks;

    public class UserManager : BaseUserManager
    {
        /// <summary>Initializes a new instance of the <see cref="UserManager" /> class.</summary>
        /// <param name="cryptoProvider">The crypto provider.</param>
        /// <param name="userRepository">The user repository.</param>
        public UserManager(ICryptoProvider cryptoProvider, IUserRepository userRepository)
            : base(cryptoProvider, userRepository)
        {
        }

        /// <summary>Authenticates the user using username and password.</summary>
        /// <param name="username">The username.</param>
        /// <param name="password">The password.</param>
        /// <returns>The client principal.</returns>
        public async override Task<ISentinelPrincipal> AuthenticateUserWithPasswordAsync(string username, string password)
        {
            var user = await this.UserRepository.GetUser(username);

            if (user != null && this.CryptoProvider.ValidateHash(password, user.Password))
            {
                var principal =
                    new SentinelPrincipal(
                        new SentinelIdentity(
                            AuthenticationType.OAuth,
                            new SentinelClaim(ClaimTypes.Name, user.UserId),
                            new SentinelClaim(ClaimTypes.AuthenticationMethod, AuthenticationMethod.UserCredentials),
                            new SentinelClaim(ClaimTypes.GivenName, user.FirstName),
                            new SentinelClaim(ClaimTypes.Surname, user.LastName)));

                if (principal.Identity.IsAuthenticated)
                {
                    // TODO: Update last login date
                    //await
                    //    connection.ExecuteAsync(
                    //        "UPDATE Users SET LastLogin = @LastLogin WHERE Username = @Username",
                    //        new { LastLogin = DateTimeOffset.UtcNow, Username = user.Username },
                    //        transaction);

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
                            new SentinelClaim(ClaimTypes.Name, user.UserId),
                            new SentinelClaim(ClaimTypes.AuthenticationMethod, AuthenticationMethod.UserId),
                            new SentinelClaim(ClaimTypes.GivenName, user.FirstName),
                            new SentinelClaim(ClaimTypes.Surname, user.LastName)));

                if (principal.Identity.IsAuthenticated)
                {
                    // TODO: Update last login date
                    //await
                    //    connection.ExecuteAsync(
                    //        "UPDATE Users SET LastLogin = @LastLogin WHERE Username = @Username",
                    //        new { LastLogin = DateTimeOffset.UtcNow, Username = user.Username },
                    //        transaction);

                    return principal;
                }
            }

            return SentinelPrincipal.Anonymous;
        }
    }
}