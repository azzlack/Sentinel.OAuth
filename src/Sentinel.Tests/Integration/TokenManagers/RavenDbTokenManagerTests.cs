namespace Sentinel.Tests.Integration.TokenManagers
{
    using Common.Logging;
    using Moq;
    using NUnit.Framework;
    using Raven.Client.Embedded;
    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Core.Models.OAuth;
    using Sentinel.OAuth.Implementation.Managers;
    using Sentinel.OAuth.Implementation.Providers;
    using Sentinel.OAuth.Models.Identity;
    using Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Implementation;
    using Sentinel.OAuth.TokenManagers.RavenDbTokenRepository.Models;
    using System.Collections.Generic;
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

            var principalProvider = new PrincipalProvider(new SHA2CryptoProvider());
            var tokenRepository = new RavenDbTokenRepository(
                    new RavenDbTokenRepositoryConfiguration(new EmbeddableDocumentStore() { RunInMemory = true }, LogManager.GetLogger<RavenDbTokenManagerTests>()));
            var clientRepository = new Mock<IClientRepository>();
            clientRepository.Setup(x => x.GetClients()).ReturnsAsync(new List<IClient>() { new Client() { ClientId = "NUnit", ClientSecret = "aabbccddee", Enabled = true, RedirectUri = "http://localhost" } });
            clientRepository.Setup(x => x.GetClient("NUnit")).ReturnsAsync(new Client() { ClientId = "NUnit", ClientSecret = "aabbccddee", Enabled = true, RedirectUri = "http://localhost" });

            this.TokenManager = new TokenManager(
                LogManager.GetLogger(typeof(RavenDbTokenManagerTests)),
                userManager.Object,
                principalProvider,
                new SentinelTokenProvider(new SHA2CryptoProvider(), principalProvider),
                tokenRepository,
                clientRepository.Object);

            base.SetUp();
        }
    }
}