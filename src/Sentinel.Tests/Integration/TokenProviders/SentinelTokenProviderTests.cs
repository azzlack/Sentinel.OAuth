namespace Sentinel.Tests.Integration.TokenProviders
{
    using NUnit.Framework;

    using Sentinel.OAuth.Implementation.Providers;
    using Sentinel.OAuth.Implementation.Repositories;

    [TestFixture]
    public class SentinelTokenProviderTests : TokenProviderTests
    {
        [TestFixtureSetUp]
        public override void TestFixtureSetUp()
        {
            var cryptoProvider = new SHA2CryptoProvider();
            var principalProvider = new PrincipalProvider(cryptoProvider);
            var tokenRepository = new MemoryTokenRepository();

            this.TokenProvider = new SentinelTokenProvider(cryptoProvider, principalProvider, tokenRepository);

            base.TestFixtureSetUp();
        }
    }
}