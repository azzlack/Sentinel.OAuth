namespace Sentinel.Tests.Integration.TokenManagers
{
    using Common.Logging;
    using Moq;
    using NUnit.Framework;
    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Core.Models.OAuth;
    using Sentinel.OAuth.Implementation.Managers;
    using Sentinel.OAuth.Implementation.Providers;
    using Sentinel.OAuth.Models.Identity;
    using Sentinel.OAuth.TokenManagers.RedisTokenRepository.Implementation;
    using Sentinel.OAuth.TokenManagers.RedisTokenRepository.Models;
    using System.Collections.Generic;
    using System.Configuration;
    using System.Security.Claims;

    using Sentinel.OAuth.Core.Constants;

    [TestFixture]
    [Category("Integration")]
    public class RedisTokenManagerTests : TokenManagerTests
    {
        [SetUp]
        public override void SetUp()
        {
            var principalProvider = new PrincipalProvider(new SHA2CryptoProvider(HashAlgorithm.SHA512));
            var tokenRepository =
                new RedisTokenRepository(
                    new RedisTokenRepositoryConfiguration(
                        ConfigurationManager.AppSettings["RedisHost"],
                        4,
                        "sentinel.oauth.RedisTokenManagerTests",
                        LogManager.GetLogger(typeof(RedisTokenManagerTests))));

            this.TokenManager = new TokenManager(
                LogManager.GetLogger(typeof(RedisTokenManagerTests)),
                principalProvider,
                new SentinelTokenProvider(new SHA2CryptoProvider(HashAlgorithm.SHA512), principalProvider),
                tokenRepository);

            base.SetUp();
        }
    }
}