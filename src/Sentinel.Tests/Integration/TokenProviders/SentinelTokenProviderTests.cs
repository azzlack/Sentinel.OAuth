namespace Sentinel.Tests.Integration.TokenProviders
{
    using NUnit.Framework;

    using Sentinel.OAuth.Core.Constants;
    using Sentinel.OAuth.Implementation.Providers;
    using Sentinel.OAuth.Implementation.Repositories;

    [TestFixture]
    public class SentinelTokenProviderTests : TokenProviderTests
    {
        [TestFixtureSetUp]
        public override void TestFixtureSetUp()
        {
            var cryptoProvider = new SHA2CryptoProvider(HashAlgorithm.SHA256);
            var principalProvider = new PrincipalProvider(cryptoProvider);

            this.TokenProvider = new SentinelTokenProvider(cryptoProvider, principalProvider);

            base.TestFixtureSetUp();
        }
    }
}