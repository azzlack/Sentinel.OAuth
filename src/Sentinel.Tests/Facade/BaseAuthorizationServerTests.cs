namespace Sentinel.Tests.Facade
{
    using Coypu;
    using Microsoft.Owin.Testing;
    using Newtonsoft.Json;
    using NUnit.Framework;
    using Sentinel.OAuth.Client;
    using Sentinel.OAuth.Core.Constants.OAuth;
    using Sentinel.OAuth.Core.Models.OAuth.Http;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;

    using Sentinel.OAuth.Core.Extensions;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Implementation.Providers;

    using Scope = Sentinel.Tests.Constants.Scope;

    public abstract class BaseAuthorizationServerTests
    {
        protected TestServer Server;

        protected HttpClient Client;

        protected string SymmetricKey;

        protected IAsymmetricCryptoProvider AsymmetricCryptoProvider;

        protected EventHandler<Tuple<AccessTokenResponse, IdentityResponse>> ValidateTokenEventHandler;

        [TestFixtureSetUp]
        public virtual void TestFixtureSetUp()
        {
            this.AsymmetricCryptoProvider = new AsymmetricCryptoProvider();
        }

        [TestFixtureTearDown]
        public virtual void TestFixtureTearDown()
        {
            this.Server.Dispose();
        }

        [SetUp]
        public virtual void SetUp()
        {
            this.Client = new HttpClient(this.Server.Handler) { BaseAddress = this.Server.BaseAddress };

            Console.WriteLine("Using API URL " + this.Client.BaseAddress);
        }

        [TestCase("azzlack", "aabbccddee")]
        public async void AuthenticateResourceOwner_WhenGivenValidClientAndUserAndPassword_ShouldReturnAccessToken(string username, string password)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "oauth/token");
            request.Headers.Authorization = new BasicAuthenticationHeaderValue("NUnit", "aabbccddee");
            request.Content = new FormUrlEncodedContent(new Dictionary<string, string>()
                                                        {
                                                            { "grant_type", GrantType.Password },
                                                            { "redirect_uri", "http://localhost" },
                                                            { "scope", string.Join(" ", Scope.Read, Scope.Write) },
                                                            { "username", username },
                                                            { "password", password }
                                                        });

            Console.WriteLine("Request: {0}{1}", this.Client.BaseAddress, request.RequestUri);

            var response = await this.Client.SendAsync(request);

            Console.WriteLine("Response: {0} {1}", (int)response.StatusCode, response.ReasonPhrase);

            if (!response.IsSuccessStatusCode)
            {
                Assert.Fail(await response.Content.ReadAsStringAsync());
            }

            var content = JsonConvert.DeserializeObject<AccessTokenResponse>(await response.Content.ReadAsStringAsync());

            Assert.IsNotNullOrEmpty(content.AccessToken, "No access token returned");

            var identityRequest = new HttpRequestMessage(HttpMethod.Get, "openid/userinfo");
            identityRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", content.AccessToken);

            var identityResponse = await this.Client.SendAsync(identityRequest);
            var identityContent = await identityResponse.Content.ReadAsStringAsync();
            var identity = JsonConvert.DeserializeObject<IdentityResponse>(identityContent);

            foreach (var claim in identity)
            {
                Console.WriteLine($"{claim.Key}:{claim.Value}");
            }

            CollectionAssert.Contains(identity.Scope, Scope.Read);
            CollectionAssert.Contains(identity.Scope, Scope.Write);
        }

        [TestCase("user", "pass")]
        public async void AuthenticateResourceOwner_WhenGivenInvalidClientAndUserAndPassword_ShouldReturnInvalidGrant(string username, string password)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "oauth/token");
            request.Headers.Authorization = new BasicAuthenticationHeaderValue("NUnit", "aabbccddee");
            request.Content = new FormUrlEncodedContent(new Dictionary<string, string>()
                                                        {
                                                            { "grant_type", GrantType.Password },
                                                            { "redirect_uri", "http://localhost" },
                                                            { "username", username },
                                                            { "password", password }
                                                        });

            Console.WriteLine("Request: {0}{1}", this.Client.BaseAddress, request.RequestUri);

            var response = await this.Client.SendAsync(request);
            var content = await response.Content.ReadAsStringAsync();

            Console.WriteLine("Response: [{0} {1}] {2}", (int)response.StatusCode, response.StatusCode, content);

            Assert.IsFalse(response.IsSuccessStatusCode);
            Assert.That(content.Contains("invalid_grant"));
        }

        [TestCase("azzlack", "aabbccddee")]
        public async void AuthenticateResourceOwner_WhenGivenValidRefreshToken_ShouldReturnNewAccessToken(string username, string password)
        {
            var request1 = new HttpRequestMessage(HttpMethod.Post, "oauth/token");
            request1.Headers.Authorization = new BasicAuthenticationHeaderValue("NUnit", "aabbccddee");
            request1.Content = new FormUrlEncodedContent(new Dictionary<string, string>()
                                                        {
                                                            { "grant_type", GrantType.Password },
                                                            { "redirect_uri", "http://localhost" },
                                                            { "username", username },
                                                            { "password", password }
                                                        });

            var response1 = await this.Client.SendAsync(request1);

            Console.WriteLine("Response: {0} {1}", (int)response1.StatusCode, response1.ReasonPhrase);

            if (!response1.IsSuccessStatusCode)
            {
                Console.WriteLine(await response1.Content.ReadAsStringAsync());
            }

            var content1 = JsonConvert.DeserializeObject<AccessTokenResponse>(await response1.Content.ReadAsStringAsync());

            Assert.IsNotNullOrEmpty(content1.RefreshToken, "No refresh token returned");

            var request2 = new HttpRequestMessage(HttpMethod.Post, "oauth/token");
            request2.Headers.Authorization = new BasicAuthenticationHeaderValue("NUnit", "aabbccddee");
            request2.Content = new FormUrlEncodedContent(new Dictionary<string, string>()
                                                        {
                                                            { "grant_type", GrantType.RefreshToken },
                                                            { "redirect_uri", "http://localhost" },
                                                            { "refresh_token", content1.RefreshToken }
                                                        });

            var response2 = await this.Client.SendAsync(request2);

            Console.WriteLine("Response: {0} {1}", (int)response2.StatusCode, response2.ReasonPhrase);

            if (!response2.IsSuccessStatusCode)
            {
                Console.WriteLine(await response2.Content.ReadAsStringAsync());
            }

            var content2 = JsonConvert.DeserializeObject<AccessTokenResponse>(await response2.Content.ReadAsStringAsync());

            Assert.IsNotNullOrEmpty(content2.AccessToken, "No access token returned");
        }

        [TestCase("user", "pass")]
        public async void AuthenticateResourceOwner_WhenGivenValidClientAndInvalidRedirectUri_ShouldReturnInvalidRequest(string username, string password)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "oauth/token");
            request.Headers.Authorization = new BasicAuthenticationHeaderValue("NUnit", "aabbccddee");
            request.Content = new FormUrlEncodedContent(new Dictionary<string, string>()
                                                        {
                                                            { "grant_type", GrantType.Password },
                                                            { "username", username },
                                                            { "password", password }
                                                        });

            Console.WriteLine("Request: {0}{1}", this.Client.BaseAddress, request.RequestUri);

            var response = await this.Client.SendAsync(request);
            var content = await response.Content.ReadAsStringAsync();

            Console.WriteLine("Response: [{0} {1}] {2}", (int)response.StatusCode, response.StatusCode, content);

            Assert.That(content.Contains("invalid_request"));
        }

        [Test]
        public async void AuthenticateClientCredentials_WhenGivenValidClientIdAndSecret_ShouldReturnAccessToken()
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "oauth/token");
            request.Headers.Authorization = new BasicAuthenticationHeaderValue("NUnit", "aabbccddee");
            request.Content = new FormUrlEncodedContent(new Dictionary<string, string>()
                                                        {
                                                            { "grant_type", GrantType.ClientCredentials },
                                                            { "scope", Scope.Read }
                                                        });

            Console.WriteLine("Request: {0}{1}", this.Client.BaseAddress, request.RequestUri);

            var response = await this.Client.SendAsync(request);

            Console.WriteLine("Response: {0} {1}", (int)response.StatusCode, response.StatusCode);

            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine(await response.Content.ReadAsStringAsync());
            }

            var token = JsonConvert.DeserializeObject<AccessTokenResponse>(await response.Content.ReadAsStringAsync());

            Assert.IsNotNullOrEmpty(token.AccessToken, "No access token returned");

            var identityRequest = new HttpRequestMessage(HttpMethod.Get, "openid/userinfo");
            identityRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);

            var identityResponse = await this.Client.SendAsync(identityRequest);
            var identityContent = await identityResponse.Content.ReadAsStringAsync();
            var identity = JsonConvert.DeserializeObject<IdentityResponse>(identityContent);

            CollectionAssert.Contains(identity.Scope, Scope.Read);
        }

        [Test]
        public async void AuthenticateClientCredentials_WhenGivenInvalidClientIdAndSecret_ShouldReturnInvalidGrant()
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "oauth/token");
            request.Headers.Authorization = new BasicAuthenticationHeaderValue("NUnit66", "aabbccddee");
            request.Content = new FormUrlEncodedContent(new Dictionary<string, string>()
                                                        {
                                                            { "grant_type", GrantType.ClientCredentials },
                                                            { "scope", "http://localhost" }
                                                        });

            Console.WriteLine("Request: {0}{1}", this.Client.BaseAddress, request.RequestUri);

            var response = await this.Client.SendAsync(request);
            var content = await response.Content.ReadAsStringAsync();

            Console.WriteLine("Response: [{0} {1}] {2}", (int)response.StatusCode, response.StatusCode, content);

            Assert.IsFalse(response.IsSuccessStatusCode);
            Assert.That(content.Contains("invalid_grant"));
        }

        [Test]
        public async void GetIdentity_WhenNotAuthorized_ShouldReturn401Unauthorized()
        {
            var url = "openid/userinfo";

            var c = new HttpClient(this.Server.Handler) { BaseAddress = this.Server.BaseAddress };

            Console.WriteLine("Request: {0}{1}", c.BaseAddress, url);

            var response = await c.GetAsync(url);

            Console.WriteLine("Response: [{0} {1}] {2}", (int)response.StatusCode, response.StatusCode, await response.Content.ReadAsStringAsync());

            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Test]
        public async void GetIdentity_WhenNotAuthorized_ShouldReturnCorrectWwwAuthenticateHeader()
        {
            var url = "openid/userinfo";

            var c = new HttpClient(this.Server.Handler) { BaseAddress = this.Server.BaseAddress };

            var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Add("Accept", "application/json, text/plain, */*");
            request.Headers.Add("Accept-Encoding", "gzip, deflate, sdhc");
            request.Headers.Add("Accept-Language", "en-US, en;q=0.8, da;q=0.6, nb;q=0.4, sv;q=0.2");
            request.Headers.Add("Cache-Control", "no-cache");
            request.Headers.Add("Connection", "keep-alive");
            request.Headers.Add("Origin", "https://localhost");
            request.Headers.Add("Pragma", "no-cache");
            request.Headers.Add("Referer", "https://localhost");
            request.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.90 Safari/537.36");

            Console.WriteLine();
            Console.WriteLine("Request: {0}{1}", c.BaseAddress, url);
            Console.WriteLine("Request Headers:");
            foreach (var header in request.Headers)
            {
                Console.WriteLine("{0}: {1}", header.Key, string.Join(", ", header.Value));
            }

            Console.WriteLine();
            var response = await c.SendAsync(request);

            Console.WriteLine("Response: [{0} {1}]", (int)response.StatusCode, response.StatusCode);
            Console.WriteLine("Response Headers:");
            foreach (var header in response.Headers)
            {
                Console.WriteLine("{0}: {1}", header.Key, string.Join(", ", header.Value));
            }

            Assert.AreEqual(1, response.Headers.Count(x => x.Key == "WWW-Authenticate"));
            Assert.AreEqual("Bearer", response.Headers.First(x => x.Key == "WWW-Authenticate").Value.First());
        }

        [Test]
        public async void GetIdentity_WhenAuthenticated_ReturnsClaims()
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "oauth/token");
            request.Headers.Authorization = new BasicAuthenticationHeaderValue("NUnit", "aabbccddee");
            request.Content = new FormUrlEncodedContent(new Dictionary<string, string>()
                                                        {
                                                            { "grant_type", GrantType.Password },
                                                            { "redirect_uri", "http://localhost" },
                                                            { "scope", string.Join(" ", Scope.Read, Scope.Write) },
                                                            { "username", "azzlack" },
                                                            { "password", "aabbccddee" }
                                                        });

            Console.WriteLine("Request: {0}{1}", this.Client.BaseAddress, request.RequestUri);

            var authenticationResponse = await this.Client.SendAsync(request);

            Console.WriteLine("Response: {0} {1}", (int)authenticationResponse.StatusCode, authenticationResponse.ReasonPhrase);

            var authenticationContent = JsonConvert.DeserializeObject<AccessTokenResponse>(await authenticationResponse.Content.ReadAsStringAsync());

            Console.WriteLine();
            Console.WriteLine("Using access token: {0}", authenticationContent.AccessToken);

            var identityRequest = new HttpRequestMessage(HttpMethod.Get, "openid/userinfo");
            identityRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", authenticationContent.AccessToken);

            Console.WriteLine("Request: {0}", identityRequest.RequestUri);

            var identityResponse = await this.Client.SendAsync(identityRequest);
            var identityContent = await identityResponse.Content.ReadAsStringAsync();

            Console.WriteLine("Response: {0} {1}", (int)identityResponse.StatusCode, identityResponse.ReasonPhrase);
            if (!identityResponse.IsSuccessStatusCode)
            {
                Console.WriteLine(identityContent);
            }

            var identity = JsonConvert.DeserializeObject<IdentityResponse>(identityContent);

            Console.WriteLine("Claims:");
            foreach (var claim in identity)
            {
                Console.WriteLine("{0}: {1}", claim.Key, claim.Value);
            }

            Assert.AreEqual("azzlack", identity.Subject);
        }

        [Test]
        public async void GetIdentity_WhenUsingOpenId_ReturnsValidAccessToken()
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "oauth/token");
            request.Headers.Authorization = new BasicAuthenticationHeaderValue("NUnit", "aabbccddee");
            request.Content = new FormUrlEncodedContent(new Dictionary<string, string>()
                                                        {
                                                            { "grant_type", GrantType.Password },
                                                            { "redirect_uri", "http://localhost" },
                                                            { "username", "azzlack" },
                                                            { "password", "aabbccddee" },
                                                            { "scope", "openid readwrite" }
                                                        });

            Console.WriteLine("Request: {0}{1}", this.Client.BaseAddress, request.RequestUri);

            var authenticationResponse = await this.Client.SendAsync(request);

            Console.WriteLine("Response: {0} {1}", (int)authenticationResponse.StatusCode, authenticationResponse.ReasonPhrase);

            var authenticationContent = await authenticationResponse.Content.ReadAsStringAsync();
            var token = JsonConvert.DeserializeObject<AccessTokenResponse>(authenticationContent);

            Console.WriteLine();
            Console.WriteLine("Using access token: {0}", token.AccessToken);

            var identityRequest = new HttpRequestMessage(HttpMethod.Get, "openid/userinfo");
            identityRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);

            Console.WriteLine("Request: {0}", identityRequest.RequestUri);

            var identityResponse = await this.Client.SendAsync(identityRequest);
            var identityContent = await identityResponse.Content.ReadAsStringAsync();

            Console.WriteLine("Response: {0} {1}", (int)identityResponse.StatusCode, identityResponse.ReasonPhrase);
            if (!identityResponse.IsSuccessStatusCode)
            {
                Console.WriteLine(identityContent);
            }

            var identity = JsonConvert.DeserializeObject<IdentityResponse>(identityContent);

            Console.WriteLine();
            Console.WriteLine("UserInfo Claims:");
            foreach (var claim in identity)
            {
                Console.WriteLine("{0}: {1}", claim.Key, claim.Value);
            }

            Assert.IsNotNullOrEmpty(token.IdToken, "Server did not return an id token");

            this.ValidateTokenEventHandler?.Invoke(this, new Tuple<AccessTokenResponse, IdentityResponse>(token, identity));
        }

        [Test]
        public async void AuthenticateRefreshToken_WhenGivenValidRefreshToken_ReturnsCorrectScope()
        {
            var accessTokenRequest = new HttpRequestMessage(HttpMethod.Post, "oauth/token");
            accessTokenRequest.Headers.Authorization = new BasicAuthenticationHeaderValue("NUnit", "aabbccddee");
            accessTokenRequest.Content = new FormUrlEncodedContent(new Dictionary<string, string>()
                                                        {
                                                            { "grant_type", GrantType.Password },
                                                            { "redirect_uri", "http://localhost" },
                                                            { "username", "azzlack" },
                                                            { "password", "aabbccddee" },
                                                            { "scope", "openid readwrite" }
                                                        });

            var accessTokenResponse = await this.Client.SendAsync(accessTokenRequest);
            var accessTokenContent = await accessTokenResponse.Content.ReadAsStringAsync();
            var accessToken1 = JsonConvert.DeserializeObject<AccessTokenResponse>(accessTokenContent);

            var refreshTokenRequest = new HttpRequestMessage(HttpMethod.Post, "oauth/token");
            refreshTokenRequest.Headers.Authorization = new BasicAuthenticationHeaderValue("NUnit", "aabbccddee");
            refreshTokenRequest.Content = new FormUrlEncodedContent(new Dictionary<string, string>()
                                                        {
                                                            { "grant_type", GrantType.RefreshToken },
                                                            { "redirect_uri", "http://localhost" },
                                                            { "refresh_token", accessToken1.RefreshToken }
                                                        });

            var refreshTokenResponse = await this.Client.SendAsync(refreshTokenRequest);
            var refreshTokenContent = await refreshTokenResponse.Content.ReadAsStringAsync();
            var accessToken2 = JsonConvert.DeserializeObject<AccessTokenResponse>(refreshTokenContent);

            Console.WriteLine();
            Console.WriteLine("Using access token: {0}", accessToken2.AccessToken);

            var identityRequest = new HttpRequestMessage(HttpMethod.Get, "openid/userinfo");
            identityRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken2.AccessToken);

            Console.WriteLine("Request: {0}", identityRequest.RequestUri);

            var identityResponse = await this.Client.SendAsync(identityRequest);
            var identityContent = await identityResponse.Content.ReadAsStringAsync();

            Console.WriteLine("Response: {0} {1}", (int)identityResponse.StatusCode, identityResponse.ReasonPhrase);
            if (!identityResponse.IsSuccessStatusCode)
            {
                Console.WriteLine(identityContent);
            }

            var identity = JsonConvert.DeserializeObject<IdentityResponse>(identityContent);

            Console.WriteLine("Claims:");
            foreach (var claim in identity)
            {
                Console.WriteLine("{0}: {1}", claim.Key, claim.Value);
            }

            CollectionAssert.Contains(identity.Scope, "openid");
            CollectionAssert.Contains(identity.Scope, "readwrite");
        }

        [TestCase("azzlack", "PFJTQUtleVZhbHVlPjxNb2R1bHVzPnlidFpyM0pWS0p1L2hlUFMrV0Zla1kyYmRYVDlJMU1MeHZheTlIMW9IenRwRmI4QzJtQmUzY1EzVDhjUzE0ajJ4bk9lRkt2YVZ4Ukw5S2ozd0tOL1B3PT08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjxQPjZTRHRuS2tpamozZC9pdExYaUZtb0NDR050VWxhRTRZV2xsOXFHaXlSb2s9PC9QPjxRPjNZWGl0TmhYRkk0MTZOQ29hU2RpUldKSW5QQUU0aGYzdkVoWE5GOWFwWWM9PC9RPjxEUD55aXgvUkNROXpvT0N1SUROWExXMHJWdG5hYmdSTjlLNk5laDBIQStudzVrPTwvRFA+PERRPm9MUllXMG4zSW5wb3NaVnVGNXJ5dDlNdFNtejFuZkExVU9wS0dUeHp6bEU9PC9EUT48SW52ZXJzZVE+Qmx0UiszUTdKVGFnOHJDTVdIOXlNekE2UFE3K1dpWWR4T0o3eHBKNmF3RT08L0ludmVyc2VRPjxEPlRybVI0T0Y5OFRpQ3IvWCtKYnNGWkVqK1k0S1JyUURpSmpXdEZiT0ErRHFPTkx0cXMxWnNDMzBpZyt2LzN3ZitWTWNRK3FFRnN0bGhFOTlaWFN5cDZRPT08L0Q+PC9SU0FLZXlWYWx1ZT4=")]
        public async void GetResource_WhenGivenValidUserBasicAuthentication_ReturnsData(string username, string password)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "openid/userinfo");
            request.Headers.Authorization = new BasicAuthenticationHeaderValue(username, password);

            var response = await this.Client.SendAsync(request);

            Assert.IsTrue(response.IsSuccessStatusCode, "User was not authenticated");
        }

        [TestCase("azzlack", "eeddccbbaa")]
        public async void GetResource_WhenGivenInvalidUserBasicAuthentication_ReturnsData(string username, string password)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "openid/userinfo");
            request.Headers.Authorization = new BasicAuthenticationHeaderValue(username, password);

            var response = await this.Client.SendAsync(request);

            Assert.IsFalse(response.IsSuccessStatusCode, "User was authenticated");
        }

        [TestCase("azzlack", "PFJTQUtleVZhbHVlPjxNb2R1bHVzPnlidFpyM0pWS0p1L2hlUFMrV0Zla1kyYmRYVDlJMU1MeHZheTlIMW9IenRwRmI4QzJtQmUzY1EzVDhjUzE0ajJ4bk9lRkt2YVZ4Ukw5S2ozd0tOL1B3PT08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjxQPjZTRHRuS2tpamozZC9pdExYaUZtb0NDR050VWxhRTRZV2xsOXFHaXlSb2s9PC9QPjxRPjNZWGl0TmhYRkk0MTZOQ29hU2RpUldKSW5QQUU0aGYzdkVoWE5GOWFwWWM9PC9RPjxEUD55aXgvUkNROXpvT0N1SUROWExXMHJWdG5hYmdSTjlLNk5laDBIQStudzVrPTwvRFA+PERRPm9MUllXMG4zSW5wb3NaVnVGNXJ5dDlNdFNtejFuZkExVU9wS0dUeHp6bEU9PC9EUT48SW52ZXJzZVE+Qmx0UiszUTdKVGFnOHJDTVdIOXlNekE2UFE3K1dpWWR4T0o3eHBKNmF3RT08L0ludmVyc2VRPjxEPlRybVI0T0Y5OFRpQ3IvWCtKYnNGWkVqK1k0S1JyUURpSmpXdEZiT0ErRHFPTkx0cXMxWnNDMzBpZyt2LzN3ZitWTWNRK3FFRnN0bGhFOTlaWFN5cDZRPT08L0Q+PC9SU0FLZXlWYWx1ZT4=")]
        public async void GetResource_WhenGivenValidUserSignatureAuthentication_ReturnsData(string username, string privateKey)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "openid/userinfo");
            
            var digest = new SignatureAuthenticationDigest(username, "NUnit", "http://localhost", request.RequestUri.ToString(), DateTimeOffset.UtcNow.ToUnixTime(), Guid.NewGuid().ToString("N") );
            var signature = this.AsymmetricCryptoProvider.Sign(digest.GetData(), privateKey);
            digest.Sign(signature);

            request.Headers.Authorization = new SignatureAuthenticationHeaderValue(digest);

            var response = await this.Client.SendAsync(request);

            var userInfo = JsonConvert.DeserializeObject<IdentityResponse>(await response.Content.ReadAsStringAsync());

            Assert.IsTrue(response.IsSuccessStatusCode, "User was not authenticated");
            Assert.AreEqual(username, userInfo.Subject);
        }

        [TestCase("azzlack", "PFJTQUtleVZhbHVlPjxNb2R1bHVzPjNST202Y3hjaG5yZ2xpSzNwS1R6VDZ6cWQxVklpZUUzWVU1cWdyZWFkT3QwVHdjNHhGNncvUkJVWmh2ZVgxWUdCNjZEdC9aTWhad3Y5Z3B1eXhrTU93PT08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjxQPjdRS2ZmVHZsellnQURzdmhlZzVlak1HeFNITWhTUGdMUWhXbVk0ZWNhWTg9PC9QPjxRPjdzbzJucjYrL0krUi8rbnZhUFNNTVJESTErMlFWZXd0WlFsV0o2ZVFwSlU9PC9RPjxEUD5XcWtQTXd0dmV6QlR2VlUxMmNlWFdVWmFOemw2K1B1UTZ1VjNNVWxWaG5jPTwvRFA+PERRPlRXNE9wZzBPR3hGbTgwZmxGUEJ2WVIyak1ybGEyekc1U3BEcmVmSlE2YjA9PC9EUT48SW52ZXJzZVE+Y1R6b2NaYXAvSm54OUVkQmtWOHJYdjdVWlN3MWRLT00vYmt1ZFFRbUVMbz08L0ludmVyc2VRPjxEPkhqUmpKNnBPTWVsejZjOVFlK1ExZ2Z0RUJZM1hYVTh4Kzg5MDZlc2Y1VDFOSXV5RzNHRFQxU01OYm1xd01RNVBUVVdkRlAxREk3dXZwSUkzU01SVGNRPT08L0Q+PC9SU0FLZXlWYWx1ZT4=")]
        public async void GetResource_WhenGivenInvalidUserSignatureAuthentication_ReturnsData(string username, string privateKey)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "openid/userinfo");

            var digest = new SignatureAuthenticationDigest(username, "NUnit", "http://localhost", request.RequestUri.ToString(), DateTimeOffset.UtcNow.ToUnixTime(), Guid.NewGuid().ToString("N"));
            var signature = this.AsymmetricCryptoProvider.Sign(digest.GetData(), privateKey);
            digest.Sign(signature);

            request.Headers.Authorization = new SignatureAuthenticationHeaderValue(digest);

            var response = await this.Client.SendAsync(request);

            Assert.AreEqual(response.StatusCode, HttpStatusCode.Unauthorized, "User was authenticated");
        }

        [Test]
        public async void GetResource_WhenGivenNoUserSignatureAuthentication_ReturnsData()
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "openid/userinfo");

            request.Headers.Authorization = new AuthenticationHeaderValue("Signature", "");

            var response = await this.Client.SendAsync(request);

            Assert.AreEqual(response.StatusCode, HttpStatusCode.Unauthorized, "User was authenticated");
        }

        [TestCase("NUnit", "aabbccddee")]
        public async void GetResource_WhenGivenValidClientBasicAuthentication_ReturnsData(string username, string password)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "openid/userinfo");
            request.Headers.Authorization = new BasicAuthenticationHeaderValue(username, password);

            var response = await this.Client.SendAsync(request);

            var userInfo = JsonConvert.DeserializeObject<IdentityResponse>(await response.Content.ReadAsStringAsync());

            Assert.IsTrue(response.IsSuccessStatusCode, "Client was not authenticated");
            Assert.AreEqual(username, userInfo.Subject);
        }

        [TestCase("NUnit", "eeddccbbaa")]
        public async void GetResource_WhenGivenInvalidClientBasicAuthentication_ReturnsData(string username, string password)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "openid/userinfo");
            request.Headers.Authorization = new BasicAuthenticationHeaderValue(username, password);

            var response = await this.Client.SendAsync(request);

            Assert.AreEqual(response.StatusCode, HttpStatusCode.Unauthorized, "Client was authenticated");
        }

        [TestCase("NUnit")]
        public async void GetResource_WhenGivenInvalidClientBasicAuthentication_ReturnsData(string username)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "openid/userinfo");
            request.Headers.Authorization = new BasicAuthenticationHeaderValue(username, "");

            var response = await this.Client.SendAsync(request);

            Assert.AreEqual(response.StatusCode, HttpStatusCode.Unauthorized, "Client was authenticated");
        }

        [TestCase("NUnit", "PFJTQUtleVZhbHVlPjxNb2R1bHVzPnFKMEtXaXZWSjUxUWtKWGdIU1hidkxOTEJsa09rOE9uSWtvRTljU1FrRzhOZm5VYXBrWHpkTlEvb3FLZE9BSWxYK1hFMnNwN0xFcS9KRnJMaDRNblhRPT08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjxQPnljRXBJUDJseG1oa0hRMGRrKzRBVk1lZDhWRUFFVHN5TXgvL3NaNS9TbFU9PC9QPjxRPjFmTEVGWU1JMk1TMUJQbzYwcnYyQmhkYWNBaTI2d2Z0V1N2OVl0aUdnT2s9PC9RPjxEUD5uZ0dYTW0wejdXVklNckJZMzhmZm5vWVBIalR2dG84RHk2SmQ0RDlmTlZrPTwvRFA+PERRPk5FZEQzclhNSFp2RFY5b0ZNYVU0TXJqV0luWWVyRU9kbmFLQUlmMGlzTEU9PC9EUT48SW52ZXJzZVE+ZGQzNVh6T0RvUlZQaXQxb2REL0lKRHpXdUtYMXZrb2NjcXQ4REZGVTlwVT08L0ludmVyc2VRPjxEPkFBcC80VW1oSmFJcm9DcWJ5eXdRbDViY0xFMXNSSkwxek50dllkdGxNTCsxWVFRdWx6YzVPRkh1WUcxQW56OE8vbXU2MXNDN0dNVm04ZTVqSUp6SldRPT08L0Q+PC9SU0FLZXlWYWx1ZT4=")]
        public async void GetResource_WhenGivenValidClientSignatureAuthentication_ReturnsData(string username, string privateKey)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "openid/userinfo");

            var digest = new SignatureAuthenticationDigest(username, "NUnit", "http://localhost", request.RequestUri.ToString(), DateTimeOffset.UtcNow.ToUnixTime(), Guid.NewGuid().ToString("N"));
            var signature = this.AsymmetricCryptoProvider.Sign(digest.GetData(), privateKey);
            digest.Sign(signature);

            request.Headers.Authorization = new SignatureAuthenticationHeaderValue(digest);

            var response = await this.Client.SendAsync(request);

            var content = await response.Content.ReadAsStringAsync();
            var userInfo = JsonConvert.DeserializeObject<IdentityResponse>(content);

            Assert.IsTrue(response.IsSuccessStatusCode, "Client was not authenticated");
            Assert.AreEqual(username, userInfo.Subject);
        }
    }
}