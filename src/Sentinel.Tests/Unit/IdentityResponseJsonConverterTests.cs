namespace Sentinel.Tests.Unit
{
    using Newtonsoft.Json;

    using NUnit.Framework;

    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Models.OAuth.Http;
    using Sentinel.OAuth.Models.Identity;

    [TestFixture]
    public class IdentityResponseJsonConverterTests
    {
        [Test]
        public void WriteJson_WhenGivenValidObject_ReturnsProperJson()
        {
            var o = new IdentityResponse(new SentinelClaim(ClaimType.Name, "azzlack"), new SentinelClaim(ClaimType.Issuer, "Sentinel.OAuth"), new SentinelClaim(ClaimType.Scope, "read"), new SentinelClaim(ClaimType.Scope, "write"));

            var json = JsonConvert.SerializeObject(o);

            Assert.AreEqual("{\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name\":\"azzlack\",\"urn:oauth:issuer\":\"Sentinel.OAuth\",\"urn:oauth:scope\":\"read\",\"urn:oauth:scope\":\"write\"}", json);
        }

        [Test]
        public void ReadJson_WhenGivenValidObject_ReturnsProperJson()
        {
            var json = "{\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name\":\"azzlack\",\"urn:oauth:issuer\":\"Sentinel.OAuth\",\"urn:oauth:scope\":\"read\",\"urn:oauth:scope\":\"write\"}";

            var o = JsonConvert.DeserializeObject<IdentityResponse>(json);

            Assert.AreEqual("azzlack", o.Subject);
            Assert.AreEqual("Sentinel.OAuth", o.Issuer);
            CollectionAssert.Contains(o.Scope, "read");
            CollectionAssert.Contains(o.Scope, "write");
        }
    }
}