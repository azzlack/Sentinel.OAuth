namespace Sentinel.Tests.Integration.TokenProviders
{
    using NUnit.Framework;
    using Sentinel.OAuth.Implementation.Providers;
    using Sentinel.OAuth.Models.Providers;

    [TestFixture]
    public class JwtTokenProviderTests : TokenProviderTests
    {
        [TestFixtureSetUp]
        public override void TestFixtureSetUp()
        {
            var cryptoProvider = new SHA2CryptoProvider();

            this.TokenProvider = new JwtTokenProvider(new JwtTokenProviderConfiguration("Sentinel.OAuth.Tests", cryptoProvider.CreateHash(256)));

            base.TestFixtureSetUp();
        }
    }
}