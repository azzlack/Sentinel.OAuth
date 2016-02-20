namespace Sentinel.Tests.Facade
{
    using Coypu;
    using Newtonsoft.Json;
    using NUnit.Framework;
    using Sentinel.OAuth.Client;
    using Sentinel.OAuth.Core.Constants.OAuth;
    using Sentinel.OAuth.Core.Models.OAuth.Http;
    using System;
    using System.Collections.Generic;
    using System.Configuration;
    using System.Net;
    using System.Net.Http;
    using System.Threading.Tasks;

    [TestFixture]
    [Category("Selenium")]
    public class AuthorizationServerTests
    {
        private HttpClient client;

        [SetUp]
        public virtual void SetUp()
        {
            var baseAddress = ConfigurationManager.AppSettings["ApiUrl"];

            this.client = new HttpClient() { BaseAddress = new Uri(baseAddress) };

            Console.WriteLine("Using API URL " + this.client.BaseAddress);
        }

        [TestCase("NUnit", "http://localhost")]
        [Category("Selenium")]
        public async void GetAuthorizationCode_WhenGivenValidClientIdAndRedirectUri_ShouldReturnValidResponse(string clientId, string redirectUri)
        {
            string code;

            // Get authorization code
            using (var browser = new BrowserSession())
            {
                browser.Visit($"{this.client.BaseAddress}oauth/authorize?response_type=code&client_id={clientId}&state=&scope={Constants.Scope.Read}&redirect_uri={redirectUri}");

                Console.WriteLine("Opened authorize page");

                browser.FillIn("Username").With("user");
                browser.FillIn("Password").With("user");
                browser.ClickButton("Login");

                Console.WriteLine("Signing in");
                browser.HasContent("The application NUnit wants to access your account", new Options() { RetryInterval = TimeSpan.FromSeconds(1) });

                browser.ClickButton("Allow");

                Console.WriteLine("Accepting authorization");
                await Task.Delay(TimeSpan.FromSeconds(5));

                var uri = browser.Location;
                Console.WriteLine("Query String: {0}", uri.Query);

                Assert.Contains("code", uri.ParseQueryString().AllKeys);

                code = uri.ParseQueryString()["code"];
            }

            Assert.IsNotNullOrEmpty(code, "No authorization code returned");
        }

        [TestCase("NUnit", "http://localhost")]
        [Category("Selenium")]
        public async void GetAuthorizationCode_WhenConsentIsNotGuven_ShouldReturnErrorRedirect(string clientId, string redirectUri)
        {
            // Get authorization code
            using (var browser = new BrowserSession())
            {
                browser.Visit($"{this.client.BaseAddress}oauth/authorize?response_type=code&client_id={clientId}&state=xyz&redirect_uri={redirectUri}");

                Console.WriteLine("Opened authorize page");

                browser.FillIn("Username").With("user");
                browser.FillIn("Password").With("user");
                browser.ClickButton("Login");

                Console.WriteLine("Signing in");
                browser.HasContent("The application NUnit wants to access your account", new Options() { RetryInterval = TimeSpan.FromSeconds(1) });

                browser.ClickButton("Cancel");

                Console.WriteLine("Declining authorization");
                await Task.Delay(TimeSpan.FromSeconds(5));

                var uri = browser.Location;
                Console.WriteLine("Query String: {0}", uri.Query);

                var error = uri.ParseQueryString()["error"];
                var state = uri.ParseQueryString()["state"];

                Assert.AreEqual("access_denied", error);
                Assert.AreEqual("xyz", state);
            }
        }

        [TestCase("NUnit", "notanurl")]
        [TestCase("NUnit", "http://www.eyecatch.no")]
        [Category("Selenium")]
        public async void GetAuthorizationCode_WhenGivenValidClientAndInvalidRedirectUri_ShouldReturnInvalidRequest(string clientId, string redirectUri)
        {
            // Get authorization code
            using (var browser = new BrowserSession())
            {
                browser.Visit($"{this.client.BaseAddress}oauth/authorize?response_type=code&client_id={clientId}&state=&scope={Constants.Scope.Read}&redirect_uri={redirectUri}");

                Console.WriteLine("Opened authorize page");

                Assert.That(browser.HasContent("invalid_request"));
            }
        }

        [TestCase("NUnit", "NUnit", "http://localhost")]
        [Category("Selenium")]
        public async void GetAccessToken_WhenGivenValidAuthorizationCodeAndInvalidRedirectUri_ShouldReturnInvalidGrant(string clientId, string clientSecret, string redirectUri)
        {
            var code = string.Empty;

            // Get authorization code
            using (var browser = new BrowserSession())
            {
                var url = string.Format("{0}oauth/authorize?response_type=code&client_id={1}&redirect_uri={2}", this.client.BaseAddress, clientId, redirectUri);

                browser.Visit(url);

                Console.WriteLine("Opened authorize page: {0}", url);

                browser.FillIn("Username").With("user");
                browser.FillIn(GrantType.Password).With("user");
                browser.ClickButton("Login");

                Console.WriteLine("Signing in");
                browser.HasContent("The application NUnit wants to access your account", new Options() { RetryInterval = TimeSpan.FromSeconds(1) });

                browser.ClickButton("Allow");

                Console.WriteLine("Accepting authorization");
                await Task.Delay(TimeSpan.FromSeconds(5));

                var uri = browser.Location;
                Console.WriteLine("Query String: {0}", uri.Query);

                Assert.Contains("code", uri.ParseQueryString().AllKeys);

                code = uri.ParseQueryString()["code"];
            }

            var request = new HttpRequestMessage(HttpMethod.Post, "oauth/token");
            request.Headers.Authorization = new BasicAuthenticationHeaderValue(clientId, clientSecret);
            request.Content = new FormUrlEncodedContent(new Dictionary<string, string>()
                                                        {
                                                            { "grant_type", GrantType.AuthorizationCode },
                                                            { "redirect_uri", "http://www.eyecatch.no" },
                                                            { "code", code }
                                                        });

            Console.WriteLine("Request: {0}{1}", this.client.BaseAddress, request.RequestUri);

            var response = await this.client.SendAsync(request);

            var content = await response.Content.ReadAsStringAsync();

            Console.WriteLine("Response: [{0} {1}] {2}", (int)response.StatusCode, response.StatusCode, await response.Content.ReadAsStringAsync());

            Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.AreEqual("{\"error\":\"invalid_grant\"}", content);
        }

        [TestCase("NUnit", "NUnit", "http://localhost")]
        [Category("Selenium")]
        public async void GetAccessToken_WhenGivenValidAuthorizationCodeAndNoRedirectUri_ShouldReturnInvalidRequest(string clientId, string clientSecret, string redirectUri)
        {
            var code = string.Empty;

            // Get authorization code
            using (var browser = new BrowserSession())
            {
                var url = string.Format("{0}oauth/authorize?response_type=code&client_id={1}&redirect_uri={2}", this.client.BaseAddress, clientId, redirectUri);

                browser.Visit(url);

                Console.WriteLine("Opened authorize page: {0}", url);

                browser.FillIn("Username").With("user");
                browser.FillIn(GrantType.Password).With("user");
                browser.ClickButton("Login");

                Console.WriteLine("Signing in");
                browser.HasContent("The application NUnit wants to access your account", new Options() { RetryInterval = TimeSpan.FromSeconds(1) });

                browser.ClickButton("Allow");

                Console.WriteLine("Accepting authorization");
                await Task.Delay(TimeSpan.FromSeconds(5));

                var uri = browser.Location;
                Console.WriteLine("Query String: {0}", uri.Query);

                Assert.Contains("code", uri.ParseQueryString().AllKeys);

                code = uri.ParseQueryString()["code"];
            }

            var request = new HttpRequestMessage(HttpMethod.Post, "oauth/token");
            request.Headers.Authorization = new BasicAuthenticationHeaderValue(clientId, clientSecret);
            request.Content = new FormUrlEncodedContent(new Dictionary<string, string>()
                                                        {
                                                            { "grant_type", GrantType.AuthorizationCode },
                                                            { "code", code }
                                                        });

            Console.WriteLine("Request: {0}{1}", this.client.BaseAddress, request.RequestUri);

            var response = await this.client.SendAsync(request);

            var content = await response.Content.ReadAsStringAsync();

            Console.WriteLine("Response: [{0} {1}] {2}", (int)response.StatusCode, response.StatusCode, await response.Content.ReadAsStringAsync());

            Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.AreEqual("{\"error\":\"invalid_request\"}", content);
        }

        [TestCase("NUnit", "NUnit", "http://localhost")]
        [Category("Selenium")]
        public async void GetAccessToken_WhenGivenValidAuthorizationCodeAndValidRedirectUri_ShouldReturnAccessToken(string clientId, string clientSecret, string redirectUri)
        {
            var code = string.Empty;

            // Get authorization code
            using (var browser = new BrowserSession())
            {
                var url = string.Format("{0}oauth/authorize?response_type=code&client_id={1}&redirect_uri={2}", this.client.BaseAddress, clientId, redirectUri);

                browser.Visit(url);

                Console.WriteLine("Opened authorize page: {0}", url);

                browser.FillIn("Username").With("user");
                browser.FillIn(GrantType.Password).With("user");
                browser.ClickButton("Login");

                Console.WriteLine("Signing in");
                browser.HasContent("The application NUnit wants to access your account", new Options() { RetryInterval = TimeSpan.FromSeconds(1) });

                browser.ClickButton("Allow");

                Console.WriteLine("Accepting authorization");
                await Task.Delay(TimeSpan.FromSeconds(5));

                var uri = browser.Location;
                Console.WriteLine("Query String: {0}", uri.Query);

                Assert.Contains("code", uri.ParseQueryString().AllKeys);

                code = uri.ParseQueryString()["code"];
            }

            var request = new HttpRequestMessage(HttpMethod.Post, "oauth/token");
            request.Headers.Authorization = new BasicAuthenticationHeaderValue(clientId, clientSecret);
            request.Content = new FormUrlEncodedContent(new Dictionary<string, string>()
                                                        {
                                                            { "grant_type", GrantType.AuthorizationCode },
                                                            { "redirect_uri", redirectUri },
                                                            { "code", code }
                                                        });

            Console.WriteLine("Request: {0}{1}", this.client.BaseAddress, request.RequestUri);

            var response = await this.client.SendAsync(request);

            var content = await response.Content.ReadAsStringAsync();
            var accessTokenResponse = JsonConvert.DeserializeObject<AccessTokenResponse>(content);

            Console.WriteLine("Response: [{0} {1}] {2}", (int)response.StatusCode, response.StatusCode, await response.Content.ReadAsStringAsync());

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.IsNotNullOrEmpty(accessTokenResponse.AccessToken);
            Assert.IsNotNullOrEmpty(accessTokenResponse.RefreshToken);
        }

        [TestCase("NUnit", "NUnit", "http://localhost")]
        [Category("Selenium")]
        public async void GetAccessToken_WhenGivenValidAuthorizationCodeAndOpenIdScope_ShouldReturnIdToken(string clientId, string clientSecret, string redirectUri)
        {
            var code = string.Empty;

            // Get authorization code
            using (var browser = new BrowserSession())
            {
                var url = $"{this.client.BaseAddress}oauth/authorize?response_type=code&client_id={clientId}&redirect_uri={redirectUri}&scope=openid";

                browser.Visit(url);

                Console.WriteLine("Opened authorize page: {0}", url);

                browser.FillIn("Username").With("user");
                browser.FillIn(GrantType.Password).With("user");
                browser.ClickButton("Login");

                Console.WriteLine("Signing in");
                browser.HasContent("The application NUnit wants to access your account", new Options() { RetryInterval = TimeSpan.FromSeconds(1) });

                browser.ClickButton("Allow");

                Console.WriteLine("Accepting authorization");
                await Task.Delay(TimeSpan.FromSeconds(5));

                var uri = browser.Location;
                Console.WriteLine("Query String: {0}", uri.Query);

                Assert.Contains("code", uri.ParseQueryString().AllKeys);

                code = uri.ParseQueryString()["code"];
            }

            var request = new HttpRequestMessage(HttpMethod.Post, "oauth/token");
            request.Headers.Authorization = new BasicAuthenticationHeaderValue(clientId, clientSecret);
            request.Content = new FormUrlEncodedContent(new Dictionary<string, string>()
                                                        {
                                                            { "grant_type", GrantType.AuthorizationCode },
                                                            { "redirect_uri", redirectUri },
                                                            { "code", code }
                                                        });

            Console.WriteLine("Request: {0}{1}", this.client.BaseAddress, request.RequestUri);

            var response = await this.client.SendAsync(request);

            var content = await response.Content.ReadAsStringAsync();
            var accessTokenResponse = JsonConvert.DeserializeObject<AccessTokenResponse>(content);

            Console.WriteLine("Response: [{0} {1}] {2}", (int)response.StatusCode, response.StatusCode, await response.Content.ReadAsStringAsync());

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.IsNotNullOrEmpty(accessTokenResponse.IdToken);
        }
    }
}