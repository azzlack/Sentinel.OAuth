namespace Sentinel.Tests.Facade
{
    using System;
    using System.Configuration;
    using System.Net.Http;

    using Moq;

    using NUnit.Framework;

    using Sentinel.OAuth.Client;
    using Sentinel.OAuth.Client.Interfaces;

    [TestFixture]
    [Category("Facade")]
    public class SentinelOAuthClientTests
    {
        private IOAuthClient client;

        [SetUp]
        public void SetUp()
        {
            var apiSettings = new Mock<ISentinelClientSettings>();
            apiSettings.Setup(x => x.Url).Returns(new Uri(ConfigurationManager.AppSettings["ApiUrl"]));
            apiSettings.Setup(x => x.ClientId).Returns("NUnit");
            apiSettings.Setup(x => x.ClientSecret).Returns("NUnit");
            apiSettings.Setup(x => x.RedirectUri).Returns("http://localhost");

            this.client = new SentinelOAuthClient(apiSettings.Object);
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
        [ExpectedException(typeof(Exception))]
        public async void Authenticate_WhenGivenInvalidApplicationCredentials_ShouldNotReturnAccessToken()
        {
            var apiSettings = new Mock<ISentinelClientSettings>();
            apiSettings.Setup(x => x.Url).Returns(new Uri(ConfigurationManager.AppSettings["ApiUrl"]));
            apiSettings.Setup(x => x.ClientId).Returns("NUnit");
            apiSettings.Setup(x => x.ClientSecret).Returns("sngldsnvkløsdnkdslgjklds");
            apiSettings.Setup(x => x.RedirectUri).Returns("http://localhost");

            var client = new SentinelOAuthClient(apiSettings.Object);

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
        [ExpectedException(typeof(Exception))]
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
        [ExpectedException(typeof(Exception))]
        public async void Authenticate_WhenGivenInvalidRefreshToken_ShouldThrowException()
        {
            await this.client.RefreshAuthentication(Guid.NewGuid().ToString("N"));
        }
    }
}