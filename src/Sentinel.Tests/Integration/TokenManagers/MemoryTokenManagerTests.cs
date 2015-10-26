namespace Sentinel.Tests.Integration.TokenManagers
{
    using Common.Logging;
    using NUnit.Framework;
    using Sentinel.OAuth.Core.Constants;
    using Sentinel.OAuth.Implementation.Managers;
    using Sentinel.OAuth.Implementation.Providers;
    using Sentinel.OAuth.Implementation.Repositories;

    [TestFixture]
    [Category("Integration")]
    public class MemoryTokenManagerTests : TokenManagerTests
    {
        [SetUp]
        public override void SetUp()
        {
            var principalProvider = new PrincipalProvider(new SHA2CryptoProvider(HashAlgorithm.SHA512));
            var tokenRepository = new MemoryTokenRepository();

            this.TokenManager = new TokenManager(
                LogManager.GetLogger(typeof(MemoryTokenManagerTests)),
                principalProvider,
                new SentinelTokenProvider(new SHA2CryptoProvider(HashAlgorithm.SHA512), principalProvider),
                tokenRepository);

            base.SetUp();
        }
    }
}