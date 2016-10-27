namespace Sentinel.Tests.Unit
{
    using System.Net;

    using NUnit.Framework;

    using Sentinel.OAuth.Core.Models;

    [TestFixture]
    public class BasicAuthenticationDigestTests
    {
        [TestCase("NUnit", "http://localhost", "PFJTQUtleVZhbHVlPjxNb2R1bHVzPnlidFpyM0pWS0p1L2hlUFMrV0Zla1kyYmRYVDlJMU1MeHZheTlIMW9IenRwRmI4QzJtQmUzY1EzVDhjUzE0ajJ4bk9lRkt2YVZ4Ukw5S2ozd0tOL1B3PT08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjxQPjZTRHRuS2tpamozZC9pdExYaUZtb0NDR050VWxhRTRZV2xsOXFHaXlSb2s9PC9QPjxRPjNZWGl0TmhYRkk0MTZOQ29hU2RpUldKSW5QQUU0aGYzdkVoWE5GOWFwWWM9PC9RPjxEUD55aXgvUkNROXpvT0N1SUROWExXMHJWdG5hYmdSTjlLNk5laDBIQStudzVrPTwvRFA+PERRPm9MUllXMG4zSW5wb3NaVnVGNXJ5dDlNdFNtejFuZkExVU9wS0dUeHp6bEU9PC9EUT48SW52ZXJzZVE+Qmx0UiszUTdKVGFnOHJDTVdIOXlNekE2UFE3K1dpWWR4T0o3eHBKNmF3RT08L0ludmVyc2VRPjxEPlRybVI0T0Y5OFRpQ3IvWCtKYnNGWkVqK1k0S1JyUURpSmpXdEZiT0ErRHFPTkx0cXMxWnNDMzBpZyt2LzN3ZitWTWNRK3FFRnN0bGhFOTlaWFN5cDZRPT08L0Q+PC9SU0FLZXlWYWx1ZT4=")]
        public void GetCipher_WhenGivenValidCipher_ReturnsCipher(string clientId, string redirectUri, string password)
        {
            var digest = new BasicAuthenticationDigest(
                             "azzlack",
                             new BasicAuthenticationCipher(clientId, redirectUri, password));

            var cipher = digest.GetCipher();

            Assert.AreEqual(clientId, cipher.ClientId);
            Assert.AreEqual(redirectUri, cipher.RedirectUri);
            Assert.AreEqual(password, cipher.Password);
        }

        [TestCase("NUnit", "http://localhost", "PFJTQUtleVZhbHVlPjxNb2R1bHVzPnlidFpyM0pWS0p1L2hlUFMrV0Zla1kyYmRYVDlJMU1MeHZheTlIMW9IenRwRmI4QzJtQmUzY1EzVDhjUzE0ajJ4bk9lRkt2YVZ4Ukw5S2ozd0tOL1B3PT08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjxQPjZTRHRuS2tpamozZC9pdExYaUZtb0NDR050VWxhRTRZV2xsOXFHaXlSb2s9PC9QPjxRPjNZWGl0TmhYRkk0MTZOQ29hU2RpUldKSW5QQUU0aGYzdkVoWE5GOWFwWWM9PC9RPjxEUD55aXgvUkNROXpvT0N1SUROWExXMHJWdG5hYmdSTjlLNk5laDBIQStudzVrPTwvRFA+PERRPm9MUllXMG4zSW5wb3NaVnVGNXJ5dDlNdFNtejFuZkExVU9wS0dUeHp6bEU9PC9EUT48SW52ZXJzZVE+Qmx0UiszUTdKVGFnOHJDTVdIOXlNekE2UFE3K1dpWWR4T0o3eHBKNmF3RT08L0ludmVyc2VRPjxEPlRybVI0T0Y5OFRpQ3IvWCtKYnNGWkVqK1k0S1JyUURpSmpXdEZiT0ErRHFPTkx0cXMxWnNDMzBpZyt2LzN3ZitWTWNRK3FFRnN0bGhFOTlaWFN5cDZRPT08L0Q+PC9SU0FLZXlWYWx1ZT4=")]
        public void GetCipher_WhenGivenValidEncodedCipher_ReturnsCipher(string clientId, string redirectUri, string password)
        {
            var digest = new BasicAuthenticationDigest(
                             "azzlack",
                             $"client_id={WebUtility.UrlEncode(clientId)}&redirect_uri={WebUtility.UrlEncode(redirectUri)}&password={WebUtility.UrlEncode(password)}");

            var cipher = digest.GetCipher();

            Assert.AreEqual(clientId, cipher.ClientId);
            Assert.AreEqual(redirectUri, cipher.RedirectUri);
            Assert.AreEqual(password, cipher.Password);
        }
    }
}