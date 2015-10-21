namespace Sentinel.Tests.Integration.TokenManagers
{
    using Common.Logging;
    using Moq;
    using NUnit.Framework;
    using Raven.Client.Embedded;
    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Implementation.Managers;
    using Sentinel.OAuth.Implementation.Providers;
    using Sentinel.OAuth.Models.Identity;
    using Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Implementation;
    using Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models;
    using System.Security.Claims;

    [TestFixture]
    [Category("Integration")]
    public class RavenDbTokenManagerTests : TokenManagerTests
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
            var tokenRepository = new RavenDbTokenRepository(
                    new RavenDbTokenRepositoryConfiguration(new EmbeddableDocumentStore() { RunInMemory = true }, LogManager.GetLogger<RavenDbTokenManagerTests>()));

            this.TokenManager = new TokenManager(
                LogManager.GetLogger(typeof(RavenDbTokenManagerTests)),
                userManager.Object,
                principalProvider,
                new SentinelTokenProvider(new PBKDF2CryptoProvider(), principalProvider, tokenRepository),
                tokenRepository);

            base.SetUp();
        }
    }
}