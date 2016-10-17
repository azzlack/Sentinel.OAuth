namespace Sentinel.Tests.Integration.ClientManagers
{
    using NUnit.Framework;
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using System;
    using System.Diagnostics;

    using Sentinel.OAuth.Core.Extensions;
    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Implementation.Providers;

    public abstract class ClientManagerTests
    {
        private Stopwatch testFixtureStopwatch;

        private Stopwatch testStopwatch;

        protected IClientManager ClientManager { get; set; }

        protected IAsymmetricCryptoProvider AsymmetricCryptoProvider { get; set; }

        [TestFixtureSetUp]
        public virtual void TestFixtureSetUp()
        {
            this.AsymmetricCryptoProvider = new AsymmetricCryptoProvider();

            this.testFixtureStopwatch = new Stopwatch();
            this.testFixtureStopwatch.Start();
        }

        [TestFixtureTearDown]
        public virtual void TestFixtureTearDown()
        {
            this.testFixtureStopwatch.Stop();

            Console.WriteLine();
            Console.WriteLine($"Time taken for all tests: {this.testFixtureStopwatch.Elapsed.ToString("g")}");
            Console.WriteLine($"##teamcity[buildStatisticValue key='{this.GetType().Name}' value='{this.testFixtureStopwatch.ElapsedMilliseconds}']");
        }

        [SetUp]
        public virtual void SetUp()
        {
            this.testStopwatch = new Stopwatch();
            this.testStopwatch.Start();
        }

        [TearDown]
        public virtual void TearDown()
        {
            this.testStopwatch.Stop();

            Console.WriteLine();
            Console.WriteLine($"Time taken for test: {this.testStopwatch.Elapsed.ToString("g")}");
            Console.WriteLine($"##teamcity[buildStatisticValue key='{this.GetType().Name}.{TestContext.CurrentContext.Test.Name}' value='{this.testStopwatch.ElapsedMilliseconds}']");
        }

        [Test]
        public async void Authenticate_WhenGivenValidClientIdAndScope_ReturnsAuthenticatedIdentity()
        {
            var user = await this.ClientManager.AuthenticateClientAsync("NUnit", new string[0]);

            Assert.IsTrue(user.Identity.IsAuthenticated, "The client was not authenticated");
        }

        [Test]
        public async void Authenticate_WhenGivenInvalidClientIdAndScope_ReturnsNotAuthenticatedIdentity()
        {
            var user = await this.ClientManager.AuthenticateClientAsync("NUnit56", new string[0]);

            Assert.IsFalse(user.Identity.IsAuthenticated, "The client was authenticated");
        }

        [Test]
        public async void Authenticate_WhenGivenValidClientIdAndRedirectUri_ReturnsAuthenticatedIdentity()
        {
            var user = await this.ClientManager.AuthenticateClientAsync("NUnit", "http://localhost");

            Assert.IsTrue(user.Identity.IsAuthenticated, "The client was not authenticated");
        }

        [Test]
        public async void Authenticate_WhenGivenValidClientIdAndInvalidRedirectUri_ReturnsNotAuthenticatedIdentity()
        {
            var user = await this.ClientManager.AuthenticateClientAsync("NUnit", "http://localhostbcs");

            Assert.IsFalse(user.Identity.IsAuthenticated, "The client was authenticated");
        }

        [Test]
        public async void Authenticate_WhenGivenValidClientIdAndSecret_ReturnsAuthenticatedIdentity()
        {
            var user = await this.ClientManager.AuthenticateClientCredentialsAsync("NUnit", "aabbccddee");

            Assert.IsTrue(user.Identity.IsAuthenticated, "The client was not authenticated");
        }

        [Test]
        public async void Authenticate_WhenGivenDisabledClientId_ReturnsNotAuthenticatedIdentity()
        {
            var user = await this.ClientManager.AuthenticateClientCredentialsAsync("NUnit2", "aabbccddee");

            Assert.IsFalse(user.Identity.IsAuthenticated, "The client was authenticated");
        }

        [Test]
        public async void Authenticate_WhenGivenInvalidClientIdAndSecret_ReturnsNotAuthenticatedIdentity()
        {
            var user = await this.ClientManager.AuthenticateClientCredentialsAsync("NUnit", "xyz");

            Assert.IsFalse(user.Identity.IsAuthenticated, "The client was authenticated");
        }

        [TestCase("NUnit", "aabbccddee")]
        public async void AuthenticateClientWithApiKeyAsync_WhenGivenValidBasicAuthenticationDigest_ReturnsAuthenticatedIdentity(string username, string password)
        {
            var client = await this.ClientManager.AuthenticateClientCredentialsAsync(new BasicAuthenticationDigest(username, password));

            Assert.IsTrue(client.Identity.IsAuthenticated, "The client was not authenticated");
        }

        [TestCase("NUnit", "")]
        [TestCase("NUnit", "eeddccbbaa")]
        public async void AuthenticateClientWithApiKeyAsync_WhenGivenInvalidBasicAuthenticationDigest_ReturnsNotAuthenticatedIdentity(string username, string password)
        {
            var client = await this.ClientManager.AuthenticateClientCredentialsAsync(new BasicAuthenticationDigest(username, password));

            Assert.IsFalse(client.Identity.IsAuthenticated, "The client was authenticated");
        }

        [TestCase("NUnit", "PFJTQUtleVZhbHVlPjxNb2R1bHVzPnFKMEtXaXZWSjUxUWtKWGdIU1hidkxOTEJsa09rOE9uSWtvRTljU1FrRzhOZm5VYXBrWHpkTlEvb3FLZE9BSWxYK1hFMnNwN0xFcS9KRnJMaDRNblhRPT08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjxQPnljRXBJUDJseG1oa0hRMGRrKzRBVk1lZDhWRUFFVHN5TXgvL3NaNS9TbFU9PC9QPjxRPjFmTEVGWU1JMk1TMUJQbzYwcnYyQmhkYWNBaTI2d2Z0V1N2OVl0aUdnT2s9PC9RPjxEUD5uZ0dYTW0wejdXVklNckJZMzhmZm5vWVBIalR2dG84RHk2SmQ0RDlmTlZrPTwvRFA+PERRPk5FZEQzclhNSFp2RFY5b0ZNYVU0TXJqV0luWWVyRU9kbmFLQUlmMGlzTEU9PC9EUT48SW52ZXJzZVE+ZGQzNVh6T0RvUlZQaXQxb2REL0lKRHpXdUtYMXZrb2NjcXQ4REZGVTlwVT08L0ludmVyc2VRPjxEPkFBcC80VW1oSmFJcm9DcWJ5eXdRbDViY0xFMXNSSkwxek50dllkdGxNTCsxWVFRdWx6YzVPRkh1WUcxQW56OE8vbXU2MXNDN0dNVm04ZTVqSUp6SldRPT08L0Q+PC9SU0FLZXlWYWx1ZT4=")]
        public async void AuthenticateClientWithApiKeyAsync_WhenGivenValidApiKeyAuthenticationDigest_ReturnsAuthenticatedIdentity(string username, string privateKey)
        {
            var digest  = new SignatureAuthenticationDigest(username, username, "http://localhost", "/openid/userinfo", DateTimeOffset.UtcNow.ToUnixTime(), Guid.NewGuid().ToString("N"));
            var signature = this.AsymmetricCryptoProvider.Sign(digest.GetData(), privateKey);
            digest.Sign(signature);

            var client = await this.ClientManager.AuthenticateClientWithSignatureAsync(digest);

            Assert.IsTrue(client.Identity.IsAuthenticated, "The client was not authenticated");
        }

        [TestCase("NUnit", "PFJTQUtleVZhbHVlPjxNb2R1bHVzPjNST202Y3hjaG5yZ2xpSzNwS1R6VDZ6cWQxVklpZUUzWVU1cWdyZWFkT3QwVHdjNHhGNncvUkJVWmh2ZVgxWUdCNjZEdC9aTWhad3Y5Z3B1eXhrTU93PT08L01vZHVsdXM+PEV4cG9uZW50PkFRQUI8L0V4cG9uZW50PjxQPjdRS2ZmVHZsellnQURzdmhlZzVlak1HeFNITWhTUGdMUWhXbVk0ZWNhWTg9PC9QPjxRPjdzbzJucjYrL0krUi8rbnZhUFNNTVJESTErMlFWZXd0WlFsV0o2ZVFwSlU9PC9RPjxEUD5XcWtQTXd0dmV6QlR2VlUxMmNlWFdVWmFOemw2K1B1UTZ1VjNNVWxWaG5jPTwvRFA+PERRPlRXNE9wZzBPR3hGbTgwZmxGUEJ2WVIyak1ybGEyekc1U3BEcmVmSlE2YjA9PC9EUT48SW52ZXJzZVE+Y1R6b2NaYXAvSm54OUVkQmtWOHJYdjdVWlN3MWRLT00vYmt1ZFFRbUVMbz08L0ludmVyc2VRPjxEPkhqUmpKNnBPTWVsejZjOVFlK1ExZ2Z0RUJZM1hYVTh4Kzg5MDZlc2Y1VDFOSXV5RzNHRFQxU01OYm1xd01RNVBUVVdkRlAxREk3dXZwSUkzU01SVGNRPT08L0Q+PC9SU0FLZXlWYWx1ZT4=")]
        public async void AuthenticateClientWithApiKeyAsync_WhenGivenInvalidApiKeyAuthenticationDigest_ReturnsNotAuthenticatedIdentity(string username, string privateKey)
        {
            var digest = new SignatureAuthenticationDigest(username, username, "http://localhost", "/openid/userinfo", DateTimeOffset.UtcNow.ToUnixTime(), Guid.NewGuid().ToString("N"));
            var signature = this.AsymmetricCryptoProvider.Sign(digest.GetData(), privateKey);
            digest.Sign(signature);

            var client = await this.ClientManager.AuthenticateClientWithSignatureAsync(digest);

            Assert.IsFalse(client.Identity.IsAuthenticated, "The client was authenticated");
        }
    }
}