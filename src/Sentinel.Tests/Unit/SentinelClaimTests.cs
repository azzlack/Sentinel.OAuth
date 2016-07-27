namespace Sentinel.Tests.Unit
{
    using System;
    using System.Security.Claims;

    using NUnit.Framework;

    using Sentinel.OAuth.Models.Identity;

    [System.ComponentModel.Category("Unit")]
    [TestFixture]
    public class SentinelClaimTests
    {
        [TestCase("sub", ClaimTypes.NameIdentifier)]
        [TestCase("unique_name", ClaimTypes.Name)]
        [TestCase("given_name", ClaimTypes.GivenName)]
        [TestCase("family_name", ClaimTypes.Surname)]
        [TestCase("email", ClaimTypes.Email)]
        [TestCase("role", ClaimTypes.Role)]
        public void ToClaim_WhenMappingFromSentinel_ReturnsCorrectClaims(string type, string expectedType)
        {
            var s = new SentinelClaim(type, "test");
            var r = (Claim)s;

            Assert.AreEqual(expectedType, r.Type);

            Console.WriteLine($"{s.Type} => {r.Type}");
        }

        [TestCase(ClaimTypes.NameIdentifier, "nameid")]
        [TestCase(ClaimTypes.Name, "unique_name")]
        [TestCase(ClaimTypes.GivenName, "given_name")]
        [TestCase(ClaimTypes.Surname, "family_name")]
        [TestCase(ClaimTypes.Email, "email")]
        [TestCase(ClaimTypes.Role, "role")]
        public void ToSentinelClaim_WhenMappingFromSentinel_ReturnsCorrectClaims(string type, string expectedType)
        {
            var s = new Claim(type, "test");
            var r = (SentinelClaim)s;

            Assert.AreEqual(expectedType, r.Type);

            Console.WriteLine($"{s.Type} => {r.Type}");
        }
    }
}