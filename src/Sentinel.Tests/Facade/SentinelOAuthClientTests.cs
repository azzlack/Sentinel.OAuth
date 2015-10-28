namespace Sentinel.Tests.Facade
{
    using Microsoft.Owin.Security.OAuth;
    using Microsoft.Owin.Testing;
    using Moq;
    using NUnit.Framework;
    using Owin;
    using Sentinel.OAuth.Client;
    using Sentinel.OAuth.Client.Interfaces;
    using Sentinel.OAuth.Core.Interfaces.Models;
    using Sentinel.OAuth.Core.Interfaces.Repositories;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Core.Models.OAuth;
    using Sentinel.OAuth.Extensions;
    using System;
    using System.Collections.Generic;
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
            var client = new Client()
            {
                ClientId = "NUnit",
                ClientSecret = "10000:gW7zpVeugKl8IFu7TcpPskcgQjy4185eAwBk9fFlZK6JNd1I45tLyCYtJrzWzE+kVCUP7lMSY8o808EjUgfavBzYU/ZtWypcdCdCJ0BMfMcf8Mk+XIYQCQLiFpt9Rjrf5mAY86NuveUtd1yBdPjxX5neMXEtquNYhu9I6iyzcN4=:Lk2ZkpmTDkNtO/tsB/GskMppdAX2bXehP+ED4oLis0AAv3Q1VeI8KL0SxIIWdxjKH0NJKZ6qniRFkfZKZRS2hS4SB8oyB34u/jyUlmv+RZGZSt9nJ9FYJn1percd/yFA7sSQOpkGljJ6OTwdthe0Bw0A/8qlKHbO2y2M5BFgYHY=",
                RedirectUri = "http://localhost",
                Enabled = true
            };
            var user = new User()
            {
                UserId = "azzlack",
                Password = "10000:gW7zpVeugKl8IFu7TcpPskcgQjy4185eAwBk9fFlZK6JNd1I45tLyCYtJrzWzE+kVCUP7lMSY8o808EjUgfavBzYU/ZtWypcdCdCJ0BMfMcf8Mk+XIYQCQLiFpt9Rjrf5mAY86NuveUtd1yBdPjxX5neMXEtquNYhu9I6iyzcN4=:Lk2ZkpmTDkNtO/tsB/GskMppdAX2bXehP+ED4oLis0AAv3Q1VeI8KL0SxIIWdxjKH0NJKZ6qniRFkfZKZRS2hS4SB8oyB34u/jyUlmv+RZGZSt9nJ9FYJn1percd/yFA7sSQOpkGljJ6OTwdthe0Bw0A/8qlKHbO2y2M5BFgYHY=",
                FirstName = "Ove",
                LastName = "Andersen",
                Enabled = true
            };

            var clientRepository = new Mock<IClientRepository>();
            clientRepository.Setup(x => x.GetClient("NUnit")).ReturnsAsync(client);
            clientRepository.Setup(x => x.GetClients()).ReturnsAsync(new List<IClient>() { client });

            var userRepository = new Mock<IUserRepository>();
            userRepository.Setup(x => x.GetUser("azzlack")).ReturnsAsync(user);
            userRepository.Setup(x => x.GetUsers()).ReturnsAsync(new List<IUser>() { user });

            this.server = TestServer.Create(
                app =>
                {
                    app.UseSentinelAuthorizationServer(new SentinelAuthorizationServerOptions()
                    {
                        ClientRepository = clientRepository.Object,
                        UserRepository = userRepository.Object,
                        IssuerUri = new Uri("http://sentinel.oauth")
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
            apiSettings.Setup(x => x.ClientSecret).Returns("aabbccddee");
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

        [TestCase("azzlack", "aabbccddee")]
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

        [TestCase("azzlack", "usbdsgbvdser")]
        [ExpectedException(typeof(SecurityException))]
        public async void Authenticate_WhenGivenInvalidUsernameAndPassword_ShouldThrowException(string userName, string password)
        {
            await this.client.Authenticate(userName, password);
        }

        [TestCase("azzlack", "aabbccddee")]
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

        [TestCase("azzlack", "aabbccddee")]
        public async void Authenticate_WhenGivenOpenIdScopeAndValidRefreshToken_ShouldReturnIdToken(string userName, string password)
        {
            var token = await this.client.Authenticate(userName, password, new[] { "openid" });

            var newToken = await this.client.RefreshAuthentication(token.RefreshToken);

            Assert.IsNotNullOrEmpty(newToken.IdToken, "The token endpoint did not return an ID token");
        }

        [Test]
        [ExpectedException(typeof(SecurityException))]
        public async void Authenticate_WhenGivenInvalidRefreshToken_ShouldThrowException()
        {
            await this.client.RefreshAuthentication(Guid.NewGuid().ToString("N"));
        }

        [TestCase("azzlack", "aabbccddee")]
        public async void GetIdentity_WhenGivenValidUsernameAndPassword_ShouldReturnIdentity(string userName, string password)
        {
            var token = await this.client.Authenticate(userName, password);
            var identity = await this.client.GetIdentity(token.AccessToken);

            Assert.IsNotNull(identity);
            Assert.AreEqual(userName, identity.Subject);
        }
    }
}