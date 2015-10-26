namespace Sentinel.Tests.Unit
{
    using NUnit.Framework;
    using Sentinel.OAuth.Core.Extensions;
    using Sentinel.OAuth.Core.Models.Tokens;
    using System;

    [TestFixture]
    public class JsonWebTokenTests
    {
        [TestCase("HS256", "NUnit", "https://sentinel.oauth/", 1445850630, 1445854230, "azzlack", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1bmlxdWVfbmFtZSI6ImF6emxhY2siLCJhdXRobWV0aG9kIjoidXNlcl9jcmVkZW50aWFscyIsImdpdmVuX25hbWUiOiJPdmUiLCJmYW1pbHlfbmFtZSI6IkFuZGVyc2VuIiwidXJuOm9hdXRoOmNsaWVudCI6Ik5Vbml0IiwidXJuOm9hdXRoOmdyYW50dHlwZSI6InBhc3N3b3JkIiwidXJuOm9hdXRoOnNjb3BlIjoib3BlbmlkIiwic3ViIjoiYXp6bGFjayIsImF0X2hhc2giOiJlSEZ1YVVjek9VaHdiMjExV1ZRclVtdGtRM2hqTjJoMFlUTnJiMEpyYzFKWVVHdGhLMWRMT1hJemVFNVNPVVZrVDFOeFJDOUdOSG95U2xWcWEyMUxNUT09IiwiaXNzIjoiaHR0cHM6Ly9zZW50aW5lbC5vYXV0aC8iLCJhdWQiOiJOVW5pdCIsImV4cCI6MTQ0NTg1NDIzMCwibmJmIjoxNDQ1ODUwNjMwfQ.m0m0iyCqssawb44VE8ANUGJMIBppUx1AnSCbSCfNdeM")]
        [TestCase("RS256", "https://contoso.com", "https://sts.windows.net/e481747f-5da7-4538-cbbe-67e57f7d214e/", 1391210850, 1391214450, "21749daae2a91137c259191622fa1", "eyJhbGciOiJSUzI1NiIsIng1dCI6IjdkRC1nZWNOZ1gxWmY3R0xrT3ZwT0IyZGNWQSIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2NvbnRvc28uY29tIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvZTQ4MTc0N2YtNWRhNy00NTM4LWNiYmUtNjdlNTdmN2QyMTRlLyIsIm5iZiI6MTM5MTIxMDg1MCwiZXhwIjoxMzkxMjE0NDUwLCJzdWIiOiIyMTc0OWRhYWUyYTkxMTM3YzI1OTE5MTYyMmZhMSJ9.C4Ny4LeVjEEEybcA1SVaFYFS6nH-Ezae_RrTXUYInjXGt-vBOkAa2ryb-kpOlzU_R4Ydce9tKDNp1qZTomXgHjl-cKybAz0Ut90-dlWgXGvJYFkWRXJ4J0JyS893EDwTEHYaAZH_lCBvoYPhXexD2yt1b-73xSP6oxVlc_sMvz3DY__1Y_OyvbYrThHnHglxvjh88x_lX7RN-Bq82ztumxy97rTWaa_1WJgYuy7h7okD24FtsD9PPLYAply0ygl31ReI0FZOdX12Hl4THJm4uI_4_bPXL6YR2oZhYWp-4POWIPHzG9c_GL8asBjoDY9F5q1ykQiotUBESoMML7_N1g")]
        public void Construct_WhenGivenValidJwt_ReturnsJwt(string expectedAlgorithm, string expectedAudience, string expectedIssuer, long expectedValidFrom, long expectedExpires, string expectedSubject, string token)
        {
            var jwt = new JsonWebToken(token);

            Assert.AreEqual(expectedAlgorithm, jwt.Header.Algorithm);
            Assert.AreEqual("JWT", jwt.Header.Type);
            Assert.AreEqual(expectedAudience, jwt.Payload.Audience);
            Assert.AreEqual(new Uri(expectedIssuer), jwt.Payload.Issuer);
            Assert.AreEqual(expectedValidFrom, jwt.Payload.ValidFrom.ToUnixTime());
            Assert.AreEqual(expectedExpires, jwt.Payload.Expires.ToUnixTime());
            Assert.AreEqual(expectedSubject, jwt.Payload.Subject);
            Assert.IsNotNullOrEmpty(jwt.Signature);
        }
    }
}