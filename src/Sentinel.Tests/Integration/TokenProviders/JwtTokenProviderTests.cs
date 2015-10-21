namespace Sentinel.Tests.Integration.TokenProviders
{
    using Moq;
    using NUnit.Framework;
    using Sentinel.OAuth.ClientManagers.SqlServerClientManager.Models;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Implementation.Providers;
    using Sentinel.OAuth.Implementation.Repositories;
    using Sentinel.OAuth.Models.Providers;
    using System.Collections.Generic;

    [TestFixture]
    public class JwtTokenProviderTests : TokenProviderTests
    {
        [TestFixtureSetUp]
        public override void TestFixtureSetUp()
        {
            var cryptoProvider = new SHA2CryptoProvider();
            var tokenRepository = new MemoryTokenRepository();
            var clientRepository = new Mock<IClientRepository>();
            clientRepository.Setup(x => x.GetClients())
                .ReturnsAsync(
                    new List<IClient>()
                        {
                            new Client() { ClientId = "NUnit", RedirectUri = "http://localhost" }
                        });

            this.TokenProvider = new JwtTokenProvider(new JwtTokenProviderConfiguration("Sentinel.OAuth.Tests", cryptoProvider.CreateHash(256)), tokenRepository, clientRepository.Object);

            base.TestFixtureSetUp();
        }
    }
}