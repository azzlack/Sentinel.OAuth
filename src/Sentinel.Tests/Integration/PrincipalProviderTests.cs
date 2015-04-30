namespace Sentinel.Tests.Integration
{
    using System;
    using System.Collections.Generic;
    using System.Security.Claims;

    using NUnit.Framework;

    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Models.Identity;
    using Sentinel.OAuth.Implementation;

    [TestFixture]
    [Category("Integration")]
    public class PrincipalProviderTests
    {
        private IPrincipalProvider principalProvider;

        [SetUp]
        public void SetUp()
        {
            this.principalProvider = new PrincipalProvider(new PBKDF2CryptoProvider());
        }

        [TestCase("bgfdskbnfkldnklfde")]
        [TestCase("123456789")]
        public void Encrypt_WhenGivenValidPrincipal_ReturnsEncryptedPrincipal(string key)
        {
            var c1 = new JsonPrincipal(new JsonIdentity(new List<JsonClaim>() { new JsonClaim(ClaimTypes.Name, "azzlack") }));

            var r = this.principalProvider.Encrypt(c1, key);

            Console.WriteLine("Encrypted: {0}", r);

            Assert.IsNotNullOrEmpty(r);
        }

        [TestCase("bgfdskbnfkldnklfde")]
        [TestCase("123456789")]
        public void Decrypt_WhenGivenValidPrincipal_ReturnsDecryptedPrincipal(string key)
        {
            var c1 = new JsonPrincipal(new JsonIdentity(new List<JsonClaim>() { new JsonClaim(ClaimTypes.Name, "azzlack") }));

            var r = this.principalProvider.Encrypt(c1, key);

            Console.WriteLine("Encrypted: {0}", r);

            var c2 = this.principalProvider.Decrypt(r, key);

            Assert.AreEqual(c1.Identity.Name, c2.Identity.Name);
        }
    }
}