namespace Sentinel.Tests.Integration.TokenManagers
{
    using Common.Logging;
    using Moq;
    using NUnit.Framework;
    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Implementation.Managers;
    using Sentinel.OAuth.Implementation.Providers;
    using Sentinel.OAuth.Implementation.Repositories;
    using Sentinel.OAuth.Models.Identity;
    using System.Security.Claims;

    [TestFixture]
    [Category("Integration")]
    public class MemoryTokenManagerTests : TokenManagerTests
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

            var principalProvider = new PrincipalProvider(new PBKDF2CryptoProvider());
            var tokenRepository = new MemoryTokenRepository();

            this.TokenManager = new TokenManager(
                LogManager.GetLogger(typeof(MemoryTokenManagerTests)),
                userManager.Object,
                principalProvider,
                new SentinelTokenProvider(new PBKDF2CryptoProvider(), principalProvider, tokenRepository),
                tokenRepository);

            base.SetUp();
        }
    }
}