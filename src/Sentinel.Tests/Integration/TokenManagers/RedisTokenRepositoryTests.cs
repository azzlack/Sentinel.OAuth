namespace Sentinel.Tests.Integration.TokenManagers
{
    using System;
    using System.Configuration;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Common.Logging;

    using Moq;

    using NUnit.Framework;

    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Implementation;
    using Sentinel.OAuth.Models.Identity;
    using Sentinel.OAuth.TokenManagers.RedisTokenRepository.Implementation;
    using Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models;

    [TestFixture]
    [Category("Integration")]
    public class RedisTokenRepositoryTests
    {
        private ITokenManager tokenManager;

        [SetUp]
        public void SetUp()
        {
            var userManager = new Mock<IUserManager>();
            userManager.Setup(x => x.AuthenticateUserAsync(It.IsAny<string>()))
                .ReturnsAsync(new SentinelPrincipal(
                        new SentinelIdentity(
                            AuthenticationType.OAuth,
                            new SentinelClaim(ClaimTypes.Name, "azzlack"),
                            new SentinelClaim(ClaimType.Client, "NUnit"))));

            this.tokenManager = new TokenManager(
                LogManager.GetLogger(typeof(RedisTokenRepositoryTests)), 
                userManager.Object,
                new PrincipalProvider(new PBKDF2CryptoProvider()), 
                new PBKDF2CryptoProvider(), 
                new RedisTokenRepository(new RedisTokenRepositoryConfiguration(ConfigurationManager.AppSettings["RedisHost"], 4)));
        }

        [Test]
        public async void AuthenticateAuthorizationCode_WhenGivenValidIdentity_ReturnsAuthenticatedIdentity()
        {
            var code =
                await
                this.tokenManager.CreateAuthorizationCodeAsync(
                    new SentinelPrincipal(
                    new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))), 
                    TimeSpan.FromMinutes(5), 
                    "http://localhost");

            Console.WriteLine("Code: {0}", code);

            Assert.IsNotNullOrEmpty(code);

            var user = await this.tokenManager.AuthenticateAuthorizationCodeAsync("http://localhost", code);

            Assert.IsTrue(user.Identity.IsAuthenticated);
        }

        [Test]
        public async void AuthenticateAuthorizationCode_WhenGivenUsingCodeTwice_ReturnsNotAuthenticatedIdentity()
        {
            var code =
                await
                this.tokenManager.CreateAuthorizationCodeAsync(
                    new SentinelPrincipal(
                    new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                    TimeSpan.FromMinutes(5),
                    "http://localhost");

            Console.WriteLine("Code: {0}", code);

            var user = await this.tokenManager.AuthenticateAuthorizationCodeAsync("http://localhost", code);
            var user2 = await this.tokenManager.AuthenticateAuthorizationCodeAsync("http://localhost", code);

            Assert.IsFalse(user2.Identity.IsAuthenticated, "The code is possible to use twice");
        }

        [Test]
        public async void AuthenticateAccessToken_WhenGivenValidIdentity_ReturnsAuthenticatedIdentity()
        {
            var token =
                await
                this.tokenManager.CreateAccessTokenAsync(
                    new SentinelPrincipal(
                    new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))), 
                    TimeSpan.FromHours(1), 
                    "NUnit", 
                    "http://localhost");

            Console.WriteLine("Token: {0}", token);

            Assert.IsNotNullOrEmpty(token);

            var user = await this.tokenManager.AuthenticateAccessTokenAsync(token);

            Assert.IsTrue(user.Identity.IsAuthenticated);
        }

        [Test]
        public async void AuthenticateAccessToken_WhenGivenUsingExpiredToken_ReturnsNotAuthenticatedIdentity()
        {
            var token =
                await
                this.tokenManager.CreateAccessTokenAsync(
                    new SentinelPrincipal(
                    new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                    TimeSpan.FromSeconds(10),
                    "NUnit",
                    "http://localhost");

            Console.WriteLine("Token: {0}", token);

            await Task.Delay(TimeSpan.FromSeconds(10));

            var user = await this.tokenManager.AuthenticateAccessTokenAsync(token);

            Assert.IsFalse(user.Identity.IsAuthenticated, "The token is possible to use after expiration");
        }

        [Test]
        public async void AuthenticateRefreshToken_WhenGivenValidIdentity_ReturnsAuthenticatedIdentity()
        {
            var token =
                await
                this.tokenManager.CreateRefreshTokenAsync(
                    new SentinelPrincipal(
                    new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))), 
                    TimeSpan.FromDays(90), 
                    "NUnit", 
                    "http://localhost");

            Console.WriteLine("Token: {0}", token);

            Assert.IsNotNullOrEmpty(token);

            var user = await this.tokenManager.AuthenticateRefreshTokenAsync("NUnit", token, "http://localhost");

            Assert.IsTrue(user.Identity.IsAuthenticated);
        }

        [Test]
        public async void AuthenticateRefreshToken_WhenGivenUsingExpiredToken_ReturnsNotAuthenticatedIdentity()
        {
            var token =
                await
                this.tokenManager.CreateRefreshTokenAsync(
                    new SentinelPrincipal(
                    new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, "azzlack"), new SentinelClaim(ClaimType.Client, "NUnit"))),
                    TimeSpan.FromSeconds(10),
                    "NUnit",
                    "http://localhost");

            Console.WriteLine("Token: {0}", token);

            await Task.Delay(TimeSpan.FromSeconds(10));

            var user = await this.tokenManager.AuthenticateRefreshTokenAsync("NUnit", "https://localhost", token);

            Assert.IsFalse(user.Identity.IsAuthenticated, "The token is possible to use after expiration");
        }

    } 
}