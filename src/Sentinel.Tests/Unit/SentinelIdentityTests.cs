namespace Sentinel.Tests.Unit
{
    using Newtonsoft.Json;
    using NUnit.Framework;
    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Models.Identity;
    using System;

    [TestFixture]
    [Category("Unit")]
    public class SentinelIdentityTests
    {
        [Test]
        public void Deserialize_WhenGivenValidJson_ShouldReturnCorrectIdentity()
        {
            var json =
                "{\"AuthenticationType\":\"OAuth\",\"Claims\":[{\"Type\":\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name\",\"Alias\":null,\"Value\":\"ovea\"}],\"IsAuthenticated\":true,\"Name\":\"ovea\"}";

            var i = JsonConvert.DeserializeObject<SentinelIdentity>(json);

            Assert.AreEqual("OAuth", i.AuthenticationType);
            Assert.AreEqual(true, i.IsAuthenticated);
            Assert.AreEqual("ovea", i.Name);
        }

        [Test]
        public void Serialize_WhenGivenValidIdentity_ShouldReturnCorrectJson()
        {
            var i = new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimType.Name, "ovea"));

            var json = JsonConvert.SerializeObject(i);

            Console.WriteLine(json);

            Assert.AreEqual("{\"AuthenticationType\":\"OAuth\",\"Claims\":[{\"Type\":\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name\",\"Alias\":null,\"Value\":\"ovea\"}],\"IsAuthenticated\":true,\"Name\":\"ovea\"}", json);
        }
    }
}