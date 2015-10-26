namespace Sentinel.Tests.Integration.TokenProviders
{
    using System;

    using NUnit.Framework;

    using Sentinel.OAuth.Core.Constants;
    using Sentinel.OAuth.Implementation.Providers;
    using Sentinel.OAuth.Models.Providers;

    [TestFixture]
    public class JwtTokenProviderTests : TokenProviderTests
    {
        [TestFixtureSetUp]
        public override void TestFixtureSetUp()
        {
            var cryptoProvider = new SHA2CryptoProvider(HashAlgorithm.SHA256);

            this.TokenProvider = new JwtTokenProvider(new JwtTokenProviderConfiguration(cryptoProvider, new Uri("https://sentinel.oauth"), cryptoProvider.CreateHash(256)));

            base.TestFixtureSetUp();
        }
    }
}