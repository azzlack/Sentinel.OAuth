namespace Sentinel.Tests.Facade
{
    using Microsoft.Owin.Security.OAuth;
    using Microsoft.Owin.Testing;
    using Moq;
    using NUnit.Framework;
    using Owin;
    using Sentinel.OAuth.Client;
    using Sentinel.OAuth.Client.Interfaces;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Extensions;
    using Sentinel.Sample.Managers;
    using System;
    using System.Security;
    using System.Web.Http;

    [TestFixture]
    [Category("Facade")]
    public class SentinelOAuthClientTests
    {
        private TestServer server;

        private IOAuthClient client;

        [TestFixtureSetUp]
        public virtual void TestFixtureSetUp()
        {
            this.server = TestServer.Create(
                app =>
                    {
                        // The easiest way to use Sentinel
                        app.UseSentinelAuthorizationServer(new SentinelAuthorizationServerOptions()
                        {
                            ClientManager = new SimpleClientManager(),
                            UserManager = new SimpleUserManager()
                        });

                        // Start up web api
                        var httpConfig = new HttpConfiguration();
                        httpConfig.MapHttpAttributeRoutes();

                        // Configure Web API to use only Bearer token authentication.
                        httpConfig.Filters.Add(new HostAuthenticationFilter(OAuthDefaults.AuthenticationType));

                        httpConfig.EnsureInitialized();

                        app.UseWebApi(httpConfig);
                    });
        }

        [SetUp]
        public void SetUp()
        {
            var apiSettings = new Mock<ISentinelClientSettings>();
            apiSettings.Setup(x => x.Url).Returns(this.server.BaseAddress);
            apiSettings.Setup(x => x.ClientId).Returns("NUnit");
            apiSettings.Setup(x => x.ClientSecret).Returns("NUnit");
            apiSettings.Setup(x => x.RedirectUri).Returns("http://localhost");

            this.client = new SentinelOAuthClient(apiSettings.Object, this.server.Handler);
        }

        [Test]
        public async void Authenticate_WhenGivenApplicationCredentials_ShouldReturnAccessToken()
        {
            var token = await this.client.Authenticate();

            Console.WriteLine("Access Token: {0}", token.AccessToken);
            Console.WriteLine("Refresh Token: {0}", token.RefreshToken);
            Console.WriteLine("Token Type: {0}", token.TokenType);
            Console.WriteLine("Expires In: {0}s", token.ExpiresIn);

            Assert.IsNotNull(token);
            Assert.IsNotNullOrEmpty(token.AccessToken);
            Assert.IsNullOrEmpty(token.RefreshToken);
        }

        [Test]
        [ExpectedException(typeof(SecurityException))]
        public async void Authenticate_WhenGivenInvalidApplicationCredentials_ShouldNotReturnAccessToken()
        {
            var apiSettings = new Mock<ISentinelClientSettings>();
            apiSettings.Setup(x => x.Url).Returns(this.server.BaseAddress);
            apiSettings.Setup(x => x.ClientId).Returns("NUnit");
            apiSettings.Setup(x => x.ClientSecret).Returns("sngldsnvkløsdnkdslgjklds");
            apiSettings.Setup(x => x.RedirectUri).Returns("http://localhost");

            var client = new SentinelOAuthClient(apiSettings.Object, this.server.Handler);

            await client.Authenticate();
        }

        [TestCase("user", "user")]
        public async void Authenticate_WhenGivenValidUsernameAndPassword_ShouldReturnAccessToken(string userName, string password)
        {
            var token = await this.client.Authenticate(userName, password);

            Console.WriteLine("Access Token: {0}", token.AccessToken);
            Console.WriteLine("Refresh Token: {0}", token.RefreshToken);
            Console.WriteLine("Token Type: {0}", token.TokenType);
            Console.WriteLine("Expires In: {0}s", token.ExpiresIn);

            Assert.IsNotNull(token);
            Assert.IsNotNullOrEmpty(token.AccessToken);
            Assert.IsNotNullOrEmpty(token.RefreshToken);
        }

        [TestCase("user", "usbdsgbvdser")]
        [ExpectedException(typeof(SecurityException))]
        public async void Authenticate_WhenGivenInvalidUsernameAndPassword_ShouldThrowException(string userName, string password)
        {
            await this.client.Authenticate(userName, password);
        }

        [TestCase("user", "user")]
        public async void Authenticate_WhenGivenValidRefreshToken_ShouldReturnAccessToken(string userName, string password)
        {
            var token = await this.client.Authenticate(userName, password);

            var newToken = await this.client.RefreshAuthentication(token.RefreshToken);

            Assert.IsNotNull(newToken);
            Assert.IsNotNullOrEmpty(newToken.AccessToken);
            Assert.IsNotNullOrEmpty(newToken.RefreshToken);
            Assert.AreNotEqual(token.AccessToken, newToken.AccessToken);
            Assert.AreNotEqual(token.RefreshToken, newToken.RefreshToken);
        }

        [Test]
        [ExpectedException(typeof(SecurityException))]
        public async void Authenticate_WhenGivenInvalidRefreshToken_ShouldThrowException()
        {
            await this.client.RefreshAuthentication(Guid.NewGuid().ToString("N"));
        }
    }
}