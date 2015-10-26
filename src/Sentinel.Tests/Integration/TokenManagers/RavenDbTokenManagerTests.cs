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

    using Sentinel.OAuth.Core.Constants;

    [TestFixture]
    [Category("Integration")]
    public class RavenDbTokenManagerTests : TokenManagerTests
    {
        [SetUp]
        public override void SetUp()
        {
            var principalProvider = new PrincipalProvider(new SHA2CryptoProvider(HashAlgorithm.SHA256));
            var tokenRepository = new RavenDbTokenRepository(
                    new RavenDbTokenRepositoryConfiguration(new EmbeddableDocumentStore() { RunInMemory = true }, LogManager.GetLogger<RavenDbTokenManagerTests>()));

            this.TokenManager = new TokenManager(
                LogManager.GetLogger(typeof(RavenDbTokenManagerTests)),
                principalProvider,
                new SentinelTokenProvider(new SHA2CryptoProvider(HashAlgorithm.SHA256), principalProvider),
                tokenRepository);

            base.SetUp();
        }
    }
}