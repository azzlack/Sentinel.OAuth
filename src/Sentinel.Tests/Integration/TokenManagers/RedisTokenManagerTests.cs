namespace Sentinel.Tests.Integration.TokenManagers
{
    using Common.Logging;
    using Moq;
    using NUnit.Framework;
    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Implementation;
    using Sentinel.OAuth.Models.Identity;
    using Sentinel.OAuth.TokenManagers.RedisTokenRepository.Implementation;
    using Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models;
    using System.Configuration;
    using System.Security.Claims;

    [TestFixture]
    [Category("Integration")]
    public class RedisTokenManagerTests : TokenRepositoryTests
    {
        [SetUp]
        public override void SetUp()
        {
            var userManager = new Mock<IUserManager>();
            userManager.Setup(x => x.AuthenticateUserAsync(It.IsAny<string>()))
                .ReturnsAsync(new SentinelPrincipal(
                        new SentinelIdentity(
                            AuthenticationType.OAuth,
                            new SentinelClaim(ClaimTypes.Name, "azzlack"),
                            new SentinelClaim(ClaimType.Client, "NUnit"))));

            this.TokenManager = new TokenManager(
                LogManager.GetLogger(typeof(RedisTokenManagerTests)),
                userManager.Object,
                new PrincipalProvider(new PBKDF2CryptoProvider()),
                new PBKDF2CryptoProvider(),
                new RedisTokenFactory(),
                new RedisTokenRepository(new RedisTokenRepositoryConfiguration(ConfigurationManager.AppSettings["RedisHost"], 4, "sentinel.oauth", LogManager.GetLogger(typeof(RedisTokenManagerTests)))));

            base.SetUp();
        }
    }
}